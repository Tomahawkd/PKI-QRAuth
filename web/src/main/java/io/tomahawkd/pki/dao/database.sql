create database if not exists pki;
alter database pki character set utf8mb4 collate utf8mb4_general_ci;

create table if not exists system_log (
    `index` int auto_increment primary key,
    `module` varchar(255) not null,
    `level` varchar(10) not null,
    `date` timestamp default CURRENT_TIMESTAMP not null,
    `message` varchar(255) default ''
)