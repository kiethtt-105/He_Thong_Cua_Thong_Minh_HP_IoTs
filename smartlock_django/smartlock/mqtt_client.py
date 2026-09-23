# smartlock/mqtt_client.py
import os
import json
import logging

logger = logging.getLogger('smartlock.mqtt')

MQTT_BROKER_HOST = os.environ.get('MQTT_BROKER_HOST', 'localhost')
MQTT_BROKER_PORT = int(os.environ.get('MQTT_BROKER_PORT', '1883'))
MQTT_USE_TLS = os.environ.get('MQTT_BROKER_USE_TLS', '').lower() in ('1', 'true', 'yes')
MQTT_PUBLISHER_USERNAME = os.environ.get('MQTT_PUBLISHER_USERNAME', '')
MQTT_PUBLISHER_PASSWORD = os.environ.get('MQTT_PUBLISHER_PASSWORD', '')
PUBLISH_TIMEOUT_SECONDS = 3


class MqttPublishError(Exception):
    """Không publish được lệnh xuống thiết bị (broker down, timeout, v.v.)."""


def cmd_topic(device_code: str) -> str:
    return f'smartlock/{device_code}/cmd'


def status_topic_wildcard() -> str:
    return 'smartlock/+/status'


def ack_topic_wildcard() -> str:
    return 'smartlock/+/ack'


def publish_command(device_code: str, payload: dict) -> None:
    """
    Publish 1 lệnh xuống thiết bị qua MQTT (QoS 1: broker đảm bảo gửi ít nhất 1 lần).
    Dùng kiểu "connect ngắn hạn - publish - disconnect" (không giữ kết nối thường trực
    trong tiến trình web) để đơn giản và an toàn khi chạy nhiều worker (gunicorn/uwsgi).
    Raise MqttPublishError nếu không publish được - view gọi hàm này PHẢI xử lý lỗi
    này và báo cho người dùng biết lệnh chưa chắc tới được thiết bị.
    """
    try:
        import paho.mqtt.publish as mqtt_publish
    except ImportError as e:
        raise MqttPublishError('Chưa cài paho-mqtt (pip install "paho-mqtt<2").') from e

    auth = None
    if MQTT_PUBLISHER_USERNAME:
        auth = {'username': MQTT_PUBLISHER_USERNAME, 'password': MQTT_PUBLISHER_PASSWORD}

    try:
        mqtt_publish.single(
            topic=cmd_topic(device_code),
            payload=json.dumps(payload, ensure_ascii=False),
            qos=1,
            retain=False,
            hostname=MQTT_BROKER_HOST,
            port=MQTT_BROKER_PORT,
            auth=auth,
            tls={'ca_certs': None} if MQTT_USE_TLS else None,
            client_id=f'django-pub-{os.getpid()}',
        )
    except Exception as e:
        logger.warning('MQTT publish thất bại tới %s: %s', device_code, e)
        raise MqttPublishError(str(e)) from e