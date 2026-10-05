"""Quyền vào cửa - PIN khách, thẻ NFC, đầu đọc, khuôn mặt, chia sẻ khoá."""
from django.urls import path

from . import cards, faces, pins, readers, shares

urlpatterns = [
    # ---------------- Mã PIN khách ----------------
    path('devices/<uuid:device_id>/pins/', pins.device_pins, name='device-pins'),
    path('pins/<uuid:pin_id>/', pins.pin_revoke, name='pin-revoke'),

    # ---------------- Thẻ NFC / đầu đọc ----------------
    path('cards/', cards.cards_list, name='cards'),
    path('cards/<uuid:card_id>/', cards.card_detail, name='card-detail'),
    path('cards/<uuid:card_id>/devices/<uuid:device_id>/', cards.card_link, name='card-link'),
    path('devices/<uuid:device_id>/cards/', cards.card_register, name='card-register'),
    path('devices/<uuid:device_id>/nfc-readers/', readers.device_readers, name='nfc-readers'),
    path('nfc-readers/<uuid:reader_id>/', readers.reader_detail, name='nfc-reader'),

    # ---------------- Khuôn mặt ----------------
    path('devices/<uuid:device_id>/faces/', faces.device_faces, name='device-faces'),
    path('faces/<uuid:profile_id>/', faces.face_delete, name='face-delete'),

    # ---------------- Chia sẻ khoá ----------------
    path('permissions/', shares.permissions_catalog, name='permissions'),
    path('devices/<uuid:device_id>/shares/', shares.device_shares, name='device-shares'),
    path('shares/incoming/', shares.shares_incoming, name='shares-incoming'),
    path('shares/<uuid:share_id>/', shares.share_detail, name='share-detail'),
    path('shares/<uuid:share_id>/leave/', shares.share_leave, name='share-leave'),
]
