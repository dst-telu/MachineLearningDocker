import base64, os, time
from collections import defaultdict

import numpy as np
import paho.mqtt.client as mqtt
from joblib import load
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Konstanta
NONCE_LEN = 12
AD        = b""

#Mapping topik ke key [ISI DENGAN TOPIC DAN ENCRYPTION KEY, DIBAWAH INI HANYA CONTOH]
TOPIC_KEYS = {
    "xCdVDs": bytes([0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81]),
}

#Model ML
model  = load("model_svm_new.pkl")
scaler = load("scaler_new.pkl")
label_map = {0: "Diam", 1: "Jalan", 2: "Lari", 3: "Kendaraan"}

#Rate-limit cache
RATE_LIMIT = 1.0
LAST_SEEN  = defaultdict(lambda: {"payload": None, "ts": 0.0})

#Fungsi dekripsi
def try_decrypt(enc_b64: bytes, key: bytes) -> str | None:
    try:
        enc = base64.b64decode(enc_b64, validate=True)
    except Exception:
        print(" Base64 decode gagal")
        return None
    if len(enc) <= NONCE_LEN + 16:
        print(" Payload terlalu pendek")
        return None

    nonce, ct_tag = enc[:NONCE_LEN], enc[NONCE_LEN:]
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct_tag, AD)
        if b"," in pt:
            return pt.decode().strip()
    except Exception as e:
        print(f" Decrypt gagal: {e}")
    return None

#Callback MQTT
def on_connect(c, u, f, rc):
    print(" Terhubung ke broker MQTT, kode:", rc)
    c.subscribe("#")

def on_message(c, u, msg):
    if msg.topic.startswith("hasil/"):
        return

    token = msg.topic.split("/")[-1]
    now = time.monotonic()

    key = TOPIC_KEYS.get(token)
    if not key:
        print(f" Tidak ada key untuk token: {token}")
        return

    #Dekripsi
    t0_decrypt = time.perf_counter()
    plain = try_decrypt(msg.payload.strip(), key)
    t1_decrypt = time.perf_counter()
    decrypt_time_ms = (t1_decrypt - t0_decrypt) * 1000

    if plain is None:
        print(f" Tidak dapat didekripsi (topic: {msg.topic})")
        return

    if plain == LAST_SEEN[token]["payload"]:
        print(" Payload sama → dilewati")
        return
    if now - LAST_SEEN[token]["ts"] < RATE_LIMIT:
        print(" Rate limit → dilewati")
        return

    LAST_SEEN[token].update(payload=plain, ts=now)

    parts = plain.split(",")
    if len(parts) < 11:
        print(" Format data tidak lengkap:", plain)
        return

    try:
        device_time  = parts[0]
        batt_pct     = float(parts[1])
        lat          = float(parts[2])
        lon          = float(parts[3])
        temp         = float(parts[4])
        hum          = float(parts[5])
        x            = float(parts[6])
        y            = float(parts[7])
        z            = float(parts[8])
        speed        = float(parts[9])
        token_rx     = parts[10]
    except ValueError as e:
        print(f" Format data salah: {e}")
        print(" Payload:", plain)
        return

    #Cek token payload
    if token_rx != token:
        print(f" Token mismatch! MQTT={token}, Payload={token_rx}")

    #Prediksi ML
    data_scaled = scaler.transform([[x, y, z]])
    t0_ml = time.perf_counter()
    pred = model.predict(data_scaled)[0]
    t1_ml = time.perf_counter()
    ml_time_ms = (t1_ml - t0_ml) * 1000
    aktivitas = label_map.get(pred, "Tidak diketahui")

    #Output CSV 
    csv_out = (
        f"{device_time},{batt_pct:.0f},"
        f"{lat:.5f},{lon:.5f},"
        f"{temp:.2f},{hum:.2f},"
        f"{x:.2f},{y:.2f},{z:.2f},{speed:.2f},"
        f"{aktivitas}"
    )

    print(" Plaintext:", csv_out)

    #Enkripsi
    t0_encrypt = time.perf_counter()
    nonce_out   = os.urandom(NONCE_LEN)
    aesgcm_out  = AESGCM(key)
    ct_tag_out  = aesgcm_out.encrypt(nonce_out, csv_out.encode(), AD)
    enc_payload = base64.b64encode(nonce_out + ct_tag_out).decode()
    t1_encrypt = time.perf_counter()

    #Publish
    t0_pub = time.perf_counter()
    c.publish(f"hasil/{token}", enc_payload, qos=0, retain=True)
    t1_pub = time.perf_counter()

    print(f"→ hasil/{token} (len = {len(enc_payload)} B)")
    print(f" Dekripsi   : {decrypt_time_ms:.2f} ms")
    print(f" ML Prediksi: {ml_time_ms:.2f} ms")
    print(f" Enkripsi   : {(t1_encrypt - t0_encrypt)*1000:.2f} ms")
    print(f" Kirim MQTT : {(t1_pub - t0_pub)*1000:.2f} ms")
    print("--------------------------------------------------")

#Mulai MQTT client
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect("[IP BROKER MQTT]", 1883, 60)
client.loop_forever()
