create database if not exists simpleserver;
alter database simpleserver character set utf8mb4 collate utf8mb4_general_ci;
use simpleserver;

create table if not exists system_log
(
    `index`   int auto_increment primary key,
    `module`  varchar(255)                           not null,
    `level`   int                                    not null,
    `date`    timestamp    default CURRENT_TIMESTAMP not null,
    `message` varchar(255) default ''
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
    `bio`        text,
    `image_path` varchar(255)
);
