use crate::r#struct::{Certinfo, Config};
use chrono::{Datelike, Timelike};
use mysql::prelude::*;
use ocsp::common::asn1::GeneralizedTime;
use ocsp::response::{CertStatus as OcspCertStatus, CertStatusCode, CrlReason, RevokedInfo};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

pub enum DatabaseType {
    MySQL,
    PostgreSQL,
}

impl DatabaseType {
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "postgres" | "postgresql" => DatabaseType::PostgreSQL,
            _ => DatabaseType::MySQL,
        }
    }
}

pub trait Database: Send + Sync {
    fn check_cert(
        &self,
        certnum: &str,
        revoked: bool,
    ) -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>>;
    fn create_tables_if_needed(&self) -> Result<(), Box<dyn Error + Send + Sync>>;
}

pub struct MySqlDatabase {
    config: Arc<Config>,
}

impl MySqlDatabase {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    fn get_connection(&self) -> Result<mysql::Conn, mysql::Error> {
        let mut opts = mysql::OptsBuilder::new()
            .user(Some(&self.config.dbuser))
            .read_timeout(Some(Duration::new(self.config.time as u64, 0)))
            .db_name(Some(&self.config.dbname))
            .pass(Some(&self.config.dbpassword));

        if let Some(ip) = &self.config.dbip {
            opts = opts.ip_or_hostname(Some(ip));
        } else {
            opts = opts
                .prefer_socket(true)
                .socket(Some("/run/mysqld/mysqld.sock"));
        }

        if let Some(port) = self.config.dbport {
            opts = opts.tcp_port(port);
        }

        mysql::Conn::new(opts)
    }
}

impl Database for MySqlDatabase {
    fn check_cert(
        &self,
        certnum: &str,
        revoked: bool,
    ) -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>> {
        let mut conn = self.get_connection()?;

        let status = conn.exec_map(
            "SELECT status, revocation_time, revocation_reason FROM list_certs WHERE cert_num=?",
            (String::from(certnum),),
            |(status, revocation_time, revocation_reason)| Certinfo {
                status,
                revocation_time,
                revocation_reason,
            },
        )?;

        if status.is_empty() {
            warn!("Entry not found for cert {}", certnum);
            if !revoked {
                Ok(OcspCertStatus::new(CertStatusCode::Unknown, None))
            } else {
                Ok(OcspCertStatus::new(
                    CertStatusCode::Revoked,
                    Some(RevokedInfo::new(
                        GeneralizedTime::new(1970, 1, 1, 0, 0, 0).unwrap(),
                        Some(CrlReason::OcspRevokeCertHold),
                    )),
                ))
            }
        } else {
            let statut = status[0].clone();
            debug!("Entry found for cert {}, status {}", certnum, statut.status);
            if statut.status == "Revoked" {
                let time = GeneralizedTime::now();
                let date = &statut.revocation_time;
                let timenew = match date {
                    Some(mysql::Value::Date(year, month, day, hour, min, sec, _ms)) => {
                        GeneralizedTime::new(
                            i32::from(*year),
                            u32::from(*month),
                            u32::from(*day),
                            u32::from(*hour),
                            u32::from(*min),
                            u32::from(*sec),
                        )
                    }
                    _ => Ok(time),
                };
                let time = timenew.unwrap_or(time);
                let motif = statut.revocation_reason.unwrap_or_default();
                let motif: CrlReason = match motif.as_str() {
                    "key_compromise" => CrlReason::OcspRevokeKeyCompromise,
                    "ca_compromise" => CrlReason::OcspRevokeCaCompromise,
                    "affiliation_changed" => CrlReason::OcspRevokeAffChanged,
                    "superseded" => CrlReason::OcspRevokeSuperseded,
                    "cessation_of_operation" => CrlReason::OcspRevokeCessOperation,
                    "certificate_hold" => CrlReason::OcspRevokeCertHold,
                    "privilege_withdrawn" => CrlReason::OcspRevokePrivWithdrawn,
                    "aa_compromise" => CrlReason::OcspRevokeAaCompromise,
                    _ => CrlReason::OcspRevokeUnspecified,
                };
                Ok(OcspCertStatus::new(
                    CertStatusCode::Revoked,
                    Some(RevokedInfo::new(time, Some(motif))),
                ))
            } else {
                Ok(OcspCertStatus::new(CertStatusCode::Good, None))
            }
        }
    }

    fn create_tables_if_needed(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.config.create_table {
            return Ok(());
        }

        let mut conn = self.get_connection()?;

        let tables = conn.query_map("SHOW TABLES LIKE 'list_certs'", |table_name: String| {
            table_name
        })?;

        if !tables.is_empty() {
            info!("Table list_certs already exists in MySQL database");
            return Ok(());
        }

        conn.query_drop(
            "CREATE TABLE `list_certs` (
                `cert_num` varchar(50) NOT NULL,
                `revocation_time` datetime DEFAULT NULL,
                `revocation_reason` enum('unspecified','key_compromise','ca_compromise','affiliation_changed','superseded','cessation_of_operation','certificate_hold','privilege_withdrawn','aa_compromise') DEFAULT NULL,
                `status` enum('Valid','Revoked') NOT NULL DEFAULT 'Valid',
                PRIMARY KEY (`cert_num`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        )?;

        info!("Table list_certs created successfully in MySQL database");
        Ok(())
    }
}

pub struct PostgresDatabase {
    config: Arc<Config>,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl PostgresDatabase {
    pub fn new(config: Arc<Config>) -> Self {
        let runtime =
            Arc::new(tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime"));
        Self { config, runtime }
    }

    fn get_client(&self) -> Result<tokio_postgres::Client, Box<dyn Error + Send + Sync>> {
        let host = self.config.dbip.as_deref().unwrap_or("localhost");
        let port = self.config.dbport.unwrap_or(5432);

        let conn_str = format!(
            "host={} port={} user={} password={} dbname={}",
            host, port, self.config.dbuser, self.config.dbpassword, self.config.dbname
        );

        let runtime = Arc::clone(&self.runtime);

        runtime.block_on(async {
            let (client, connection) =
                tokio_postgres::connect(&conn_str, tokio_postgres::NoTls).await?;

            // Important: This task must persist for the lifetime of the client.
            // We don't need to keep the handle because the task will run
            // as long as the runtime exists.
            runtime.spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("PostgreSQL connection error: {}", e);
                }
            });

            Ok(client)
        })
    }
}

impl Database for PostgresDatabase {
    fn check_cert(
        &self,
        certnum: &str,
        revoked: bool,
    ) -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>> {
        let client = self.get_client()?;
        let runtime = Arc::clone(&self.runtime);

        let rows = runtime.block_on(async {
            client.query(
                "SELECT status, revocation_time, revocation_reason FROM ocsp_list_certs WHERE cert_num = $1",
                &[&certnum],
            ).await
        })?;

        if rows.is_empty() {
            warn!("Entry not found for cert {} in PostgreSQL", certnum);
            if !revoked {
                Ok(OcspCertStatus::new(CertStatusCode::Unknown, None))
            } else {
                Ok(OcspCertStatus::new(
                    CertStatusCode::Revoked,
                    Some(RevokedInfo::new(
                        GeneralizedTime::new(1970, 1, 1, 0, 0, 0).unwrap(),
                        Some(CrlReason::OcspRevokeCertHold),
                    )),
                ))
            }
        } else {
            let row = &rows[0];
            let status: String = row.get(0);
            debug!("Entry found for cert {}, status {}", certnum, status);

            if status == "Revoked" {
                let time = GeneralizedTime::now();

                let revocation_time: Option<chrono::NaiveDateTime> = row.get(1);
                let time = if let Some(rt) = revocation_time {
                    let year = rt.year();
                    let month = rt.month();
                    let day = rt.day();
                    let hour = rt.hour();
                    let minute = rt.minute();
                    let second = rt.second();

                    GeneralizedTime::new(year, month, day, hour, minute, second).unwrap_or(time)
                } else {
                    time
                };

                let revocation_reason: Option<String> = row.get(2);
                let motif = revocation_reason.unwrap_or_default();
                let motif: CrlReason = match motif.as_str() {
                    "key_compromise" => CrlReason::OcspRevokeKeyCompromise,
                    "ca_compromise" => CrlReason::OcspRevokeCaCompromise,
                    "affiliation_changed" => CrlReason::OcspRevokeAffChanged,
                    "superseded" => CrlReason::OcspRevokeSuperseded,
                    "cessation_of_operation" => CrlReason::OcspRevokeCessOperation,
                    "certificate_hold" => CrlReason::OcspRevokeCertHold,
                    "privilege_withdrawn" => CrlReason::OcspRevokePrivWithdrawn,
                    "aa_compromise" => CrlReason::OcspRevokeAaCompromise,
                    _ => CrlReason::OcspRevokeUnspecified,
                };

                Ok(OcspCertStatus::new(
                    CertStatusCode::Revoked,
                    Some(RevokedInfo::new(time, Some(motif))),
                ))
            } else {
                Ok(OcspCertStatus::new(CertStatusCode::Good, None))
            }
        }
    }

    fn create_tables_if_needed(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.config.create_table {
            return Ok(());
        }

        let client = self.get_client()?;
        let runtime = Arc::clone(&self.runtime);

        let exists = runtime.block_on(async {
            let rows = client
                .query(
                    "SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'ocsp_list_certs'
                )",
                    &[],
                )
                .await?;

            let exists: bool = rows[0].get(0);
            Result::<_, tokio_postgres::Error>::Ok(exists)
        })?;

        if exists {
            info!("Table ocsp_list_certs already exists in PostgreSQL database");
            return Ok(());
        }

        let types_exist = runtime.block_on(async {
            let rows = client
                .query(
                    "SELECT EXISTS (
                    SELECT FROM pg_type
                    WHERE typname = 'cert_status'
                )",
                    &[],
                )
                .await?;

            let exists: bool = rows[0].get(0);
            Result::<_, tokio_postgres::Error>::Ok(exists)
        })?;

        if !types_exist {
            runtime.block_on(async {
                client
                    .batch_execute(
                        "CREATE TYPE cert_status AS ENUM ('Valid', 'Revoked');
                         CREATE TYPE revocation_reason_enum AS ENUM (
                            'unspecified',
                            'key_compromise',
                            'ca_compromise',
                            'affiliation_changed',
                            'superseded',
                            'cessation_of_operation',
                            'certificate_hold',
                            'privilege_withdrawn',
                            'aa_compromise'
                         );",
                    )
                    .await
            })?;
        }

        runtime.block_on(async {
            client
                .batch_execute(
                    "CREATE TABLE ocsp_list_certs (
                    cert_num VARCHAR(50) PRIMARY KEY,
                    revocation_time TIMESTAMP DEFAULT NULL,
                    revocation_reason revocation_reason_enum DEFAULT NULL,
                    status cert_status NOT NULL DEFAULT 'Valid'
                );",
                )
                .await
        })?;

        info!("Table ocsp_list_certs created successfully in PostgreSQL database");
        Ok(())
    }
}

pub fn create_database(config: Arc<Config>) -> Box<dyn Database> {
    match DatabaseType::from_string(&config.db_type) {
        DatabaseType::PostgreSQL => Box::new(PostgresDatabase::new(config)),
        DatabaseType::MySQL => Box::new(MySqlDatabase::new(config)),
    }
}
