-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.django_migrations (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  app character varying NOT NULL,
  name character varying NOT NULL,
  applied timestamp with time zone NOT NULL,
  CONSTRAINT django_migrations_pkey PRIMARY KEY (id)
);
CREATE TABLE public.django_content_type (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  app_label character varying NOT NULL,
  model character varying NOT NULL,
  CONSTRAINT django_content_type_pkey PRIMARY KEY (id)
);
CREATE TABLE public.auth_permission (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  name character varying NOT NULL,
  content_type_id integer NOT NULL,
  codename character varying NOT NULL,
  CONSTRAINT auth_permission_pkey PRIMARY KEY (id),
  CONSTRAINT auth_permission_content_type_id_2f476e4b_fk_django_co FOREIGN KEY (content_type_id) REFERENCES public.django_content_type(id)
);
CREATE TABLE public.auth_group (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  name character varying NOT NULL UNIQUE,
  CONSTRAINT auth_group_pkey PRIMARY KEY (id)
);
CREATE TABLE public.auth_group_permissions (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  group_id integer NOT NULL,
  permission_id integer NOT NULL,
  CONSTRAINT auth_group_permissions_pkey PRIMARY KEY (id),
  CONSTRAINT auth_group_permissions_group_id_b120cbf9_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES public.auth_group(id),
  CONSTRAINT auth_group_permissio_permission_id_84c5c92e_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id)
);
CREATE TABLE public.smartlock_permission (
  id uuid NOT NULL,
  code character varying NOT NULL UNIQUE,
  name character varying NOT NULL,
  description text,
  is_sensitive boolean NOT NULL,
  CONSTRAINT smartlock_permission_pkey PRIMARY KEY (id)
);
CREATE TABLE public.smartlock_user (
  password character varying NOT NULL,
  last_login timestamp with time zone,
  id uuid NOT NULL,
  email character varying NOT NULL UNIQUE,
  username character varying NOT NULL UNIQUE,
  full_name character varying,
  phone character varying,
  avatar_url character varying,
  is_admin boolean NOT NULL,
  is_active boolean NOT NULL,
  email_verified boolean NOT NULL,
  created_at timestamp with time zone NOT NULL,
  updated_at timestamp with time zone NOT NULL,
  is_staff boolean NOT NULL,
  is_superuser boolean NOT NULL,
  CONSTRAINT smartlock_user_pkey PRIMARY KEY (id)
);
CREATE TABLE public.smartlock_user_groups (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  group_id integer NOT NULL,
  CONSTRAINT smartlock_user_groups_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_user_groups_user_id_c629641d_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id),
  CONSTRAINT smartlock_user_groups_group_id_1b756c15_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES public.auth_group(id)
);
CREATE TABLE public.smartlock_user_user_permissions (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  permission_id integer NOT NULL,
  CONSTRAINT smartlock_user_user_permissions_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_user_user__user_id_64594d57_fk_smartlock FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id),
  CONSTRAINT smartlock_user_user__permission_id_09d4b780_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id)
);
CREATE TABLE public.smartlock_accesscard (
  id uuid NOT NULL,
  card_uid_hash character varying NOT NULL UNIQUE,
  name character varying,
  is_active boolean NOT NULL,
  created_at timestamp with time zone NOT NULL,
  updated_at timestamp with time zone NOT NULL,
  user_id uuid NOT NULL,
  CONSTRAINT smartlock_accesscard_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_accesscard_user_id_213f2e43_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_announcement (
  id uuid NOT NULL,
  title character varying NOT NULL,
  body text NOT NULL,
  level character varying NOT NULL,
  is_active boolean NOT NULL,
  created_at timestamp with time zone NOT NULL,
  created_by_id uuid,
  CONSTRAINT smartlock_announcement_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_announceme_created_by_id_8fedec2f_fk_smartlock FOREIGN KEY (created_by_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_device (
  id uuid NOT NULL,
  device_code character varying NOT NULL UNIQUE,
  provisioning_secret_hash character varying NOT NULL,
  device_mode character varying NOT NULL,
  name character varying NOT NULL,
  mac_address character varying,
  firmware_version character varying,
  status character varying NOT NULL,
  battery_level integer NOT NULL,
  location character varying,
  last_seen_at timestamp with time zone,
  bluetooth_enabled boolean NOT NULL,
  wifi_enabled boolean NOT NULL,
  nfc_enabled boolean NOT NULL,
  created_at timestamp with time zone NOT NULL,
  updated_at timestamp with time zone NOT NULL,
  owner_id uuid,
  CONSTRAINT smartlock_device_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_device_owner_id_f6c5c9d0_fk_smartlock_user_id FOREIGN KEY (owner_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_carddeviceaccess (
  id uuid NOT NULL,
  created_at timestamp with time zone NOT NULL,
  is_active boolean NOT NULL,
  access_card_id uuid NOT NULL,
  device_id uuid NOT NULL,
  CONSTRAINT smartlock_carddeviceaccess_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_carddevice_access_card_id_bd9eaa02_fk_smartlock FOREIGN KEY (access_card_id) REFERENCES public.smartlock_accesscard(id),
  CONSTRAINT smartlock_carddevice_device_id_5c15a729_fk_smartlock FOREIGN KEY (device_id) REFERENCES public.smartlock_device(id)
);
CREATE TABLE public.smartlock_auditlog (
  id uuid NOT NULL,
  action character varying NOT NULL,
  username_attempt character varying,
  severity character varying NOT NULL,
  success boolean NOT NULL,
  ip_address inet,
  user_agent text,
  metadata jsonb,
  created_at timestamp with time zone NOT NULL,
  actor_user_id uuid,
  target_user_id uuid,
  device_id uuid,
  CONSTRAINT smartlock_auditlog_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_auditlog_actor_user_id_42c84019_fk_smartlock_user_id FOREIGN KEY (actor_user_id) REFERENCES public.smartlock_user(id),
  CONSTRAINT smartlock_auditlog_target_user_id_204eed4a_fk_smartlock_user_id FOREIGN KEY (target_user_id) REFERENCES public.smartlock_user(id),
  CONSTRAINT smartlock_auditlog_device_id_59559b9f_fk_smartlock_device_id FOREIGN KEY (device_id) REFERENCES public.smartlock_device(id)
);
CREATE TABLE public.smartlock_devicecommand (
  id uuid NOT NULL,
  command_type character varying NOT NULL,
  payload jsonb,
  status character varying NOT NULL,
  command_token_hash character varying NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  created_at timestamp with time zone NOT NULL,
  acknowledged_at timestamp with time zone,
  device_id uuid NOT NULL,
  issued_by_id uuid NOT NULL,
  CONSTRAINT smartlock_devicecommand_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_devicecomm_device_id_ba7658fb_fk_smartlock FOREIGN KEY (device_id) REFERENCES public.smartlock_device(id),
  CONSTRAINT smartlock_devicecomm_issued_by_id_ff734c48_fk_smartlock FOREIGN KEY (issued_by_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_devicestatuslog (
  id uuid NOT NULL,
  battery_level integer NOT NULL,
  signal_strength integer,
  lock_state character varying NOT NULL,
  tamper_detected boolean NOT NULL,
  temperature numeric,
  raw_payload jsonb,
  recorded_at timestamp with time zone NOT NULL,
  device_id uuid NOT NULL,
  CONSTRAINT smartlock_devicestatuslog_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_devicestat_device_id_65e64289_fk_smartlock FOREIGN KEY (device_id) REFERENCES public.smartlock_device(id)
);
CREATE TABLE public.smartlock_emailverificationtoken (
  id uuid NOT NULL,
  purpose character varying NOT NULL,
  token_hash character varying NOT NULL,
  is_used boolean NOT NULL,
  used_at timestamp with time zone,
  expires_at timestamp with time zone NOT NULL,
  created_at timestamp with time zone NOT NULL,
  user_id uuid NOT NULL,
  CONSTRAINT smartlock_emailverificationtoken_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_emailverif_user_id_47f24310_fk_smartlock FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_loginattemptlog (
  id uuid NOT NULL,
  identifier character varying NOT NULL,
  ip_address inet NOT NULL,
  user_agent text,
  success boolean NOT NULL,
  created_at timestamp with time zone NOT NULL,
  user_id uuid,
  CONSTRAINT smartlock_loginattemptlog_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_loginattemptlog_user_id_49256fa5_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_loginidentifier (
  id uuid NOT NULL,
  kind character varying NOT NULL,
  value character varying NOT NULL UNIQUE,
  updated_at timestamp with time zone NOT NULL,
  user_id uuid NOT NULL,
  CONSTRAINT smartlock_loginidentifier_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_loginidentifier_user_id_dbfef583_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_loginlockout (
  id uuid NOT NULL,
  failed_attempts integer NOT NULL,
  stage integer NOT NULL,
  locked_until timestamp with time zone,
  last_failed_at timestamp with time zone,
  last_failed_ip inet,
  warning_sent_at timestamp with time zone,
  updated_at timestamp with time zone NOT NULL,
  user_id uuid NOT NULL UNIQUE,
  CONSTRAINT smartlock_loginlockout_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_loginlockout_user_id_878ffac7_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_nfcreader (
  id uuid NOT NULL,
  reader_mode character varying NOT NULL,
  name character varying,
  is_active boolean NOT NULL,
  last_seen_at timestamp with time zone,
  created_at timestamp with time zone NOT NULL,
  updated_at timestamp with time zone NOT NULL,
  device_id uuid NOT NULL,
  CONSTRAINT smartlock_nfcreader_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_nfcreader_device_id_2fd0d3b5_fk_smartlock_device_id FOREIGN KEY (device_id) REFERENCES public.smartlock_device(id)
);
CREATE TABLE public.smartlock_nfclog (
  id uuid NOT NULL,
  event_type character varying NOT NULL,
  success boolean NOT NULL,
  ip_address inet,
  user_agent text,
  metadata jsonb,
  created_at timestamp with time zone NOT NULL,
  device_id uuid,
  nfc_tag_id uuid,
  user_id uuid,
  reader_id uuid,
  CONSTRAINT smartlock_nfclog_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_nfclog_device_id_593f0388_fk_smartlock_device_id FOREIGN KEY (device_id) REFERENCES public.smartlock_device(id),
  CONSTRAINT smartlock_nfclog_nfc_tag_id_da002fd8_fk_smartlock_accesscard_id FOREIGN KEY (nfc_tag_id) REFERENCES public.smartlock_accesscard(id),
  CONSTRAINT smartlock_nfclog_user_id_4dfa08ea_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id),
  CONSTRAINT smartlock_nfclog_reader_id_c619328a_fk_smartlock_nfcreader_id FOREIGN KEY (reader_id) REFERENCES public.smartlock_nfcreader(id)
);
CREATE TABLE public.smartlock_nfcreaderconfig (
  id uuid NOT NULL,
  auto_register boolean NOT NULL,
  grant_permission jsonb NOT NULL,
  valid_from timestamp with time zone NOT NULL,
  expires_at timestamp with time zone,
  created_at timestamp with time zone NOT NULL,
  updated_at timestamp with time zone NOT NULL,
  reader_id uuid NOT NULL UNIQUE,
  CONSTRAINT smartlock_nfcreaderconfig_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_nfcreaderc_reader_id_68f1a2fc_fk_smartlock FOREIGN KEY (reader_id) REFERENCES public.smartlock_nfcreader(id)
);
CREATE TABLE public.smartlock_nfcsession (
  id uuid NOT NULL,
  session_token character varying NOT NULL UNIQUE,
  started_at timestamp with time zone NOT NULL,
  ended_at timestamp with time zone,
  success boolean NOT NULL,
  payload jsonb,
  device_id uuid,
  nfc_tag_id uuid,
  reader_id uuid NOT NULL,
  user_id uuid,
  CONSTRAINT smartlock_nfcsession_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_nfcsession_device_id_b3f9b4a1_fk_smartlock_device_id FOREIGN KEY (device_id) REFERENCES public.smartlock_device(id),
  CONSTRAINT smartlock_nfcsession_nfc_tag_id_3194af74_fk_smartlock FOREIGN KEY (nfc_tag_id) REFERENCES public.smartlock_accesscard(id),
  CONSTRAINT smartlock_nfcsession_reader_id_146f593e_fk_smartlock FOREIGN KEY (reader_id) REFERENCES public.smartlock_nfcreader(id),
  CONSTRAINT smartlock_nfcsession_user_id_cae36ed4_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_notification (
  id uuid NOT NULL,
  type character varying NOT NULL,
  title character varying NOT NULL,
  message text NOT NULL,
  severity character varying NOT NULL,
  is_read boolean NOT NULL,
  created_at timestamp with time zone NOT NULL,
  read_at timestamp with time zone,
  device_id uuid,
  user_id uuid NOT NULL,
  CONSTRAINT smartlock_notification_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_notificati_device_id_7ddca42b_fk_smartlock FOREIGN KEY (device_id) REFERENCES public.smartlock_device(id),
  CONSTRAINT smartlock_notification_user_id_b3329deb_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_deviceaccess (
  id uuid NOT NULL,
  source character varying NOT NULL,
  valid_from timestamp with time zone NOT NULL,
  expires_at timestamp with time zone,
  is_active boolean NOT NULL,
  accepted boolean NOT NULL,
  created_at timestamp with time zone NOT NULL,
  revoked_at timestamp with time zone,
  created_by_id uuid NOT NULL,
  device_id uuid NOT NULL,
  user_id uuid NOT NULL,
  CONSTRAINT smartlock_deviceaccess_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_deviceacce_created_by_id_4a8bf19d_fk_smartlock FOREIGN KEY (created_by_id) REFERENCES public.smartlock_user(id),
  CONSTRAINT smartlock_deviceacce_device_id_a43ef9b6_fk_smartlock FOREIGN KEY (device_id) REFERENCES public.smartlock_device(id),
  CONSTRAINT smartlock_deviceaccess_user_id_8d946420_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_deviceaccess_permissions (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  deviceaccess_id uuid NOT NULL,
  permission_id uuid NOT NULL,
  CONSTRAINT smartlock_deviceaccess_permissions_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_deviceacce_deviceaccess_id_abfea8fb_fk_smartlock FOREIGN KEY (deviceaccess_id) REFERENCES public.smartlock_deviceaccess(id),
  CONSTRAINT smartlock_deviceacce_permission_id_e3279b7a_fk_smartlock FOREIGN KEY (permission_id) REFERENCES public.smartlock_permission(id)
);
CREATE TABLE public.smartlock_shareaccesscode (
  id uuid NOT NULL,
  code_encrypted character varying NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  created_at timestamp with time zone NOT NULL,
  created_by_id uuid NOT NULL,
  device_id uuid NOT NULL,
  CONSTRAINT smartlock_shareaccesscode_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_shareacces_created_by_id_25550026_fk_smartlock FOREIGN KEY (created_by_id) REFERENCES public.smartlock_user(id),
  CONSTRAINT smartlock_shareacces_device_id_b643a9f0_fk_smartlock FOREIGN KEY (device_id) REFERENCES public.smartlock_device(id)
);
CREATE TABLE public.smartlock_shareaccesscode_permissions (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  shareaccesscode_id uuid NOT NULL,
  permission_id uuid NOT NULL,
  CONSTRAINT smartlock_shareaccesscode_permissions_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_shareacces_shareaccesscode_id_c121dd34_fk_smartlock FOREIGN KEY (shareaccesscode_id) REFERENCES public.smartlock_shareaccesscode(id),
  CONSTRAINT smartlock_shareacces_permission_id_26781424_fk_smartlock FOREIGN KEY (permission_id) REFERENCES public.smartlock_permission(id)
);
CREATE TABLE public.smartlock_supportrequest (
  id uuid NOT NULL,
  action character varying NOT NULL,
  scope character varying,
  authorization_code_hash character varying NOT NULL,
  recovery_code_hash character varying,
  status character varying NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  created_at timestamp with time zone NOT NULL,
  completed_at timestamp with time zone,
  device_id uuid NOT NULL,
  processed_by_id uuid,
  requested_by_id uuid NOT NULL,
  CONSTRAINT smartlock_supportrequest_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_supportreq_device_id_2e3f5ad4_fk_smartlock FOREIGN KEY (device_id) REFERENCES public.smartlock_device(id),
  CONSTRAINT smartlock_supportreq_processed_by_id_3120e9b2_fk_smartlock FOREIGN KEY (processed_by_id) REFERENCES public.smartlock_user(id),
  CONSTRAINT smartlock_supportreq_requested_by_id_26f1cfa0_fk_smartlock FOREIGN KEY (requested_by_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.smartlock_systemsettings (
  id smallint NOT NULL,
  registration_enabled boolean NOT NULL,
  verification_token_expiry_minutes integer NOT NULL,
  share_code_expiry_minutes integer NOT NULL,
  login_lockout_stage_minutes jsonb NOT NULL,
  session_timeout_hours integer NOT NULL,
  ip_whitelist text NOT NULL,
  ip_blacklist text NOT NULL,
  updated_at timestamp with time zone NOT NULL,
  updated_by_id uuid,
  CONSTRAINT smartlock_systemsettings_pkey PRIMARY KEY (id),
  CONSTRAINT smartlock_systemsett_updated_by_id_7001e4b3_fk_smartlock FOREIGN KEY (updated_by_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.account_emailaddress (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  email character varying NOT NULL,
  verified boolean NOT NULL,
  primary boolean NOT NULL,
  user_id uuid NOT NULL,
  CONSTRAINT account_emailaddress_pkey PRIMARY KEY (id),
  CONSTRAINT account_emailaddress_user_id_2c513194_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.account_emailconfirmation (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  created timestamp with time zone NOT NULL,
  sent timestamp with time zone,
  key character varying NOT NULL UNIQUE,
  email_address_id integer NOT NULL,
  CONSTRAINT account_emailconfirmation_pkey PRIMARY KEY (id),
  CONSTRAINT account_emailconfirm_email_address_id_5b7f8c58_fk_account_e FOREIGN KEY (email_address_id) REFERENCES public.account_emailaddress(id)
);
CREATE TABLE public.django_admin_log (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  action_time timestamp with time zone NOT NULL,
  object_id text,
  object_repr character varying NOT NULL,
  action_flag smallint NOT NULL CHECK (action_flag >= 0),
  change_message text NOT NULL,
  content_type_id integer,
  user_id uuid NOT NULL,
  CONSTRAINT django_admin_log_pkey PRIMARY KEY (id),
  CONSTRAINT django_admin_log_content_type_id_c4bce8eb_fk_django_co FOREIGN KEY (content_type_id) REFERENCES public.django_content_type(id),
  CONSTRAINT django_admin_log_user_id_c564eba6_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.otp_static_staticdevice (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  name character varying NOT NULL,
  confirmed boolean NOT NULL,
  user_id uuid NOT NULL,
  throttling_failure_count integer NOT NULL CHECK (throttling_failure_count >= 0),
  throttling_failure_timestamp timestamp with time zone,
  created_at timestamp with time zone,
  last_used_at timestamp with time zone,
  CONSTRAINT otp_static_staticdevice_pkey PRIMARY KEY (id),
  CONSTRAINT otp_static_staticdevice_user_id_7f9cff2b_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.otp_static_statictoken (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  token character varying NOT NULL,
  device_id integer NOT NULL,
  CONSTRAINT otp_static_statictoken_pkey PRIMARY KEY (id),
  CONSTRAINT otp_static_statictok_device_id_74b7c7d1_fk_otp_stati FOREIGN KEY (device_id) REFERENCES public.otp_static_staticdevice(id)
);
CREATE TABLE public.otp_totp_totpdevice (
  id integer GENERATED ALWAYS AS IDENTITY NOT NULL,
  name character varying NOT NULL,
  confirmed boolean NOT NULL,
  key character varying NOT NULL,
  step smallint NOT NULL CHECK (step >= 0),
  t0 bigint NOT NULL,
  digits smallint NOT NULL CHECK (digits >= 0),
  tolerance smallint NOT NULL CHECK (tolerance >= 0),
  drift smallint NOT NULL,
  last_t bigint NOT NULL,
  user_id uuid NOT NULL,
  throttling_failure_count integer NOT NULL CHECK (throttling_failure_count >= 0),
  throttling_failure_timestamp timestamp with time zone,
  created_at timestamp with time zone,
  last_used_at timestamp with time zone,
  CONSTRAINT otp_totp_totpdevice_pkey PRIMARY KEY (id),
  CONSTRAINT otp_totp_totpdevice_user_id_0fb18292_fk_smartlock_user_id FOREIGN KEY (user_id) REFERENCES public.smartlock_user(id)
);
CREATE TABLE public.django_session (
  session_key character varying NOT NULL,
  session_data text NOT NULL,
  expire_date timestamp with time zone NOT NULL,
  CONSTRAINT django_session_pkey PRIMARY KEY (session_key)
);