import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import io
import os
import hashlib

# ------------------ إعدادات أساسية ---------------------

# مجلد تخزين الصور المشفرة
ENC_FOLDER = "encrypted_photos"
os.makedirs(ENC_FOLDER, exist_ok=True)

# مفتاح بسيط من 5 أرقام (تقدرين تغيّرينه)
PIN = "12345"   # <-- هذا اللي تشوفينه أنتي
# نحوله داخليًا لمفتاح 32 بايت مناسب لـ AES-256
def derive_key(pin: str) -> bytes:
    return hashlib.sha256(pin.encode()).digest()  # 32 bytes

KEY = derive_key(PIN)

# حساب كلمة مرور الدخول (هنا admin / 1234 كمثال)
LOGIN_USERNAME = "admin"
LOGIN_PASSWORD_HASH = hashlib.sha256("1234".encode()).hexdigest()


# ------------------ دوال مساعدة للتشفير ----------------

def pad(data: bytes) -> bytes:
    """إضافة padding بسيط بالـ 0 لكي يصبح طول البيانات من مضاعفات 16"""
    while len(data) % 16 != 0:
        data += b"\0"
    return data


def encrypt_photo_bytes(image_bytes: bytes, filename: str, key: bytes) -> str:
    """
    المهمة 4: تشفير الصورة
    """
    data = pad(image_bytes)

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(data)

    enc_filename = filename + ".enc"
    enc_path = os.path.join(ENC_FOLDER, enc_filename)

    with open(enc_path, "wb") as f:
        f.write(iv + encrypted)

    return enc_filename


def decrypt_photo_file(enc_path: str, key: bytes) -> bytes:
    """
    المهمة 5: فك التشفير
    """
    with open(enc_path, "rb") as f:
        data = f.read()

    iv = data[:16]
    ciphertext = data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    decrypted = decrypted.rstrip(b"\0")
    return decrypted


# ------------------ واجهة تسجيل الدخول ------------------

def show_login_page():
    st.title("تسجيل الدخول – معرض الصور الآمن")

    username = st.text_input("اسم المستخدم")
    password = st.text_input("كلمة المرور", type="password")

    if st.button("دخول"):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if username == LOGIN_USERNAME and password_hash == LOGIN_PASSWORD_HASH:
            st.session_state["logged_in"] = True
            st.success("تم تسجيل الدخول بنجاح ✅")
            st.experimental_rerun()
        else:
            st.error("اسم المستخدم أو كلمة المرور غير صحيحة ❌")


# ------------------ الواجهة الرئيسية للتطبيق ------------------

def show_main_app():
    st.title("📸 تطبيق معرض الصور الآمن (AES)")

    st.write("رفع الصور → تشفير AES → تخزين → استرجاع → فك التشفير → عرض")

    # ---------------- المهمة 3 + 4: رفع وتشفير الصور ----------------
    st.header("① رفع صورة وتشفيرها")

    uploaded_file = st.file_uploader("اختر صورة للتشفير", type=["jpg", "jpeg", "png"])

    if uploaded_file is not None:
        st.image(uploaded_file, caption="الصورة قبل التشفير", use_container_width=True)

        if st.button("تشفير وحفظ الصورة"):
            image_bytes = uploaded_file.read()
            filename = os.path.splitext(uploaded_file.name)[0]
            enc_filename = encrypt_photo_bytes(image_bytes, filename, KEY)
            st.success(f"تم التشفير وتخزين الملف: {enc_filename}")

    st.markdown("---")

    # ---------------- المهمة 5: فك التشفير ----------------
    st.header("② استرجاع وفك التشفير وعرض الصورة")

    enc_files = [f for f in os.listdir(ENC_FOLDER) if f.endswith(".enc")]

    if not enc_files:
        st.info("لا توجد ملفات مشفرة.")
    else:
        selected_enc = st.selectbox("اختر ملف مشفر:", enc_files)

        if st.button("فك التشفير وعرض الصورة"):
            enc_path = os.path.join(ENC_FOLDER, selected_enc)
            decrypted_bytes = decrypt_photo_file(enc_path, KEY)
            img = Image.open(io.BytesIO(decrypted_bytes))
            st.image(img, caption=f"الصورة بعد فك التشفير", use_container_width=True)
            st.success("تم فك التشفير بنجاح")


# ------------------ نقطة تشغيل التطبيق ------------------

def main():
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False
      if not st.session_state["logged_in"]:
        show_login_page()
    else:
        show_main_app()


if name == "__main__":
    main()
