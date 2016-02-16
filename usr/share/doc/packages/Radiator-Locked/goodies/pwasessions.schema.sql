-- Table: pwa_sessions
DROP TABLE pwa_sessions;
CREATE TABLE pwa_sessions
(
  acct_session_id character varying(50),
  nas_ip_address character varying(30),
  username character varying(50) NOT NULL,
  framed_ip_address character varying(30) NOT NULL,
  acct_status_type character varying(30) NOT NULL,
  called_station_id character varying(30),
  nas_port character varying(30) NOT NULL,
  nas_port_type character varying(30),
  "timestamp" timestamp with time zone NOT NULL,
  CONSTRAINT pwa_sessions_pkey PRIMARY KEY (acct_session_id, nas_ip_address)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE pwa_sessions OWNER TO radmin;
GRANT ALL ON TABLE pwa_sessions TO radmin;
GRANT SELECT ON TABLE pwa_sessions TO netman;
COMMENT ON TABLE pwa_sessions IS 'Temp store for Framed-IP-Address during Enterasys PWA session';
COMMENT ON COLUMN pwa_sessions.called_station_id IS 'This can be NULL if connecting to N-Series';
COMMENT ON COLUMN pwa_sessions.nas_port_type IS 'This can be NULL if connecting to N-Series';

--
GRANT ALL ON TABLE pwa_sessions_id_seq TO radmin;
GRANT SELECT ON TABLE pwa_sessions_id_seq TO monitor;

-- Function: tf_pwa_sessions_called_station_id()
DROP FUNCTION tf_pwa_sessions_called_station_id();
CREATE OR REPLACE FUNCTION tf_pwa_sessions_called_station_id()
  RETURNS trigger AS
$BODY$BEGIN
    NEW.called_station_id := convert_mac(NEW.called_station_id);
    RETURN NEW;
END;$BODY$
  LANGUAGE plpgsql VOLATILE
  COST 100;
ALTER FUNCTION tf_pwa_sessions_called_station_id() OWNER TO radmin;
COMMENT ON FUNCTION tf_pwa_sessions_called_station_id() IS 'Convert called_station_id to a standard MAC address format';

-- Function: tf_pwa_sessions_timestamp()
-- DROP FUNCTION tf_pwa_sessions_timestamp();
CREATE OR REPLACE FUNCTION tf_pwa_sessions_timestamp()
  RETURNS trigger AS
$BODY$BEGIN
    NEW.timestamp := date_trunc('second',current_timestamp);
    RETURN NEW;
END;$BODY$
  LANGUAGE plpgsql VOLATILE
  COST 100;
ALTER FUNCTION tf_pwa_sessions_timestamp() OWNER TO radmin;

-- Trigger: tr_pwa_sessions_called_station_id on pwa_sessions
-- DROP TRIGGER tr_pwa_sessions_called_station_id ON pwa_sessions;
CREATE TRIGGER tr_pwa_sessions_called_station_id
  BEFORE INSERT
  ON pwa_sessions
  FOR EACH ROW
  EXECUTE PROCEDURE tf_pwa_sessions_called_station_id();

-- Trigger: tr_pwa_sessions_timestamp on pwa_sessions
-- DROP TRIGGER tr_pwa_sessions_timestamp ON pwa_sessions;
CREATE TRIGGER tr_pwa_sessions_timestamp
  BEFORE INSERT
  ON pwa_sessions
  FOR EACH ROW
  EXECUTE PROCEDURE tf_pwa_sessions_timestamp();
