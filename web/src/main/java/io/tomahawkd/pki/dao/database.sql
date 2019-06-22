create database if not exists pki;
alter database pki character set utf8mb4 collate utf8mb4_general_ci;

create table if not exists system_log
(
    `index`   int auto_increment primary key,
    `module`  varchar(255)                           not null,
    `level`   varchar(10)                            not null,
    `date`    timestamp    default CURRENT_TIMESTAMP not null,
    `message` varchar(255) default ''
);

create table if not exists user_key
(
    `user_index`  int primary key,
    `public_key`  varchar(255) not null,
    `private_key` varchar(255) not null
);

# conventional user management
create table if not exists user_info
(
    `index`      int auto_increment primary key,
    `username`   varchar(255) unique not null,
    `password`   varchar(255)        not null,
    `name`       varchar(255),
    `sex`        int          default 0, # 0 -> unknown, 1 -> male, 2 -> female
    `email`      varchar(255),
    `phone`      char(11),
    `bio`        varchar(255) default '',
    `image_path` varchar(255)
);

# v2.0
create table if not exists user_log
(
    `user_index` int primary key,
    `time`       timestamp default CURRENT_TIMESTAMP not null,
    `ip`         varchar(30)                         not null,
    `device`     varchar(255)                        not null,
    `message`    varchar(255)                        not null
);