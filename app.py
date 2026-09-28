import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import cv2
import numpy as np
import requests
import streamlit as st


# -------------------------
# QR코드 읽기
# -------------------------
def read_qr(uploaded_file):
    file_bytes = np.asarray(
        bytearray(uploaded_file.read()),
        dtype=np.uint8
    )

    image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

    if image is None:
        return None

    detector = cv2.QRCodeDetector()
    text, points, _ = detector.detectAndDecode(image)

    return text.strip() if text else None


# -------------------------
# 사설 IP 및 내부망 주소 검사
# -------------------------
def check_safe_address(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("HTTP 또는 HTTPS 주소만 검사할 수 있습니다.")

    hostname = parsed.hostname

    if not hostname:
        raise ValueError("올바른 주소가 아닙니다.")

    if hostname == "localhost":
        raise ValueError("localhost 주소는 차단됩니다.")

    try:
        ip_text = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_text)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
        ):
            raise ValueError("내부망 또는 특수 목적 주소는 차단됩니다.")

    except socket.gaierror:
        raise ValueError("도메인의 IP 주소를 찾을 수 없습니다.")


# -------------------------
# 리다이렉트 추적
# -------------------------
def trace_redirects(url):
    current_url = url
    history = []

    for step in range(5):
        check_safe_address(current_url)

        response = requests.get(
            current_url,
            allow_redirects=False,
            timeout=5,
            stream=True,
            headers={
                "User-Agent": "QR-Guard/1.0"
            }
        )

        history.append({
            "step": step + 1,
            "url": current_url,
            "status": response.status_code
        })

        if response.status_code not in (301, 302, 303, 307, 308):
            response.close()

            return {
                "final_url": current_url,
                "history": history
            }

        location = response.headers.get("Location")
        response.close()

        if not location:
            break

        # /login 같은 상대주소도 처리
        current_url = urljoin(current_url, location)

    raise ValueError("리다이렉트가 너무 많습니다.")


# -------------------------
# 간단한 위험도 계산
# -------------------------
def calculate_risk(original_url, final_url, history):
    score = 0
    reasons = []

    original = urlparse(original_url)
    final = urlparse(final_url)

    if len(history) > 1:
        score += 20
        reasons.append(
            f"리다이렉트가 {len(history) - 1}회 발생했습니다."
        )

    if original.hostname != final.hostname:
        score += 30
        reasons.append("처음 주소와 최종 도메인이 다릅니다.")

    if final.scheme != "https":
        score += 20
        reasons.append("최종 주소가 HTTPS를 사용하지 않습니다.")

    suspicious_words = [
        "login",
        "verify",
        "account",
        "password",
        "payment",
        "bank"
    ]

    final_url_lower = final_url.lower()

    for word in suspicious_words:
        if word in final_url_lower:
            score += 10
            reasons.append(
                f"의심 단어가 포함되어 있습니다: {word}"
            )
            break

    score = min(score, 100)

    if score >= 60:
        level = "위험"
    elif score >= 30:
        level = "주의"
    else:
        level = "알려진 위험요소 미발견"

    if not reasons:
        reasons.append("기본 검사에서 위험요소가 발견되지 않았습니다.")

    return score, level, reasons


# -------------------------
# Streamlit 화면
# -------------------------
st.set_page_config(
    page_title="QR-Guard",
    page_icon="🛡️"
)

st.title("🛡️ QR코드 피싱 검사")

st.write(
    "QR코드 속 URL을 바로 열지 않고, "
    "리다이렉트와 최종 목적지를 검사합니다."
)

uploaded_file = st.file_uploader(
    "QR코드 이미지 선택",
    type=["png", "jpg", "jpeg"]
)

if uploaded_file is not None:
    st.image(
        uploaded_file,
        caption="업로드한 이미지",
        use_container_width=True
    )

    if st.button("QR코드 검사", type="primary"):
        qr_text = read_qr(uploaded_file)

        if not qr_text:
            st.error("QR코드를 인식하지 못했습니다.")

        elif not qr_text.startswith(("http://", "https://")):
            st.warning("이 QR코드는 웹 주소가 아닙니다.")
            st.code(qr_text)

        else:
            st.subheader("QR코드 원본 주소")
            st.code(qr_text)

            try:
                with st.spinner("최종 목적지를 확인하고 있습니다..."):
                    result = trace_redirects(qr_text)

                final_url = result["final_url"]
                history = result["history"]

                score, level, reasons = calculate_risk(
                    qr_text,
                    final_url,
                    history
                )

                if level == "위험":
                    st.error(f"{level}: 위험점수 {score}점")
                elif level == "주의":
                    st.warning(f"{level}: 위험점수 {score}점")
                else:
                    st.success(f"{level}: 위험점수 {score}점")

                st.subheader("최종 목적지")
                st.code(final_url)

                final_domain = urlparse(final_url).hostname
                st.write(f"실제 도메인: **{final_domain}**")

                st.subheader("판정 이유")

                for reason in reasons:
                    st.write(f"- {reason}")

                with st.expander("리다이렉트 이동 경로"):
                    for item in history:
                        st.write(
                            f'{item["step"]}단계: '
                            f'HTTP {item["status"]}'
                        )
                        st.code(item["url"])

                st.warning(
                    "검사 결과가 낮은 위험점수여도 완전한 안전을 "
                    "보장하지 않습니다. 비밀번호나 인증번호 입력 전 "
                    "공식 도메인을 확인하세요."
                )

            except requests.Timeout:
                st.error("대상 사이트의 응답 시간이 초과되었습니다.")

            except requests.RequestException:
                st.error("대상 사이트에 연결할 수 없습니다.")

            except ValueError as error:
                st.error(f"검사 중단: {error}")