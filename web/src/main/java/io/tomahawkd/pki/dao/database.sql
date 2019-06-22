create database if not exists pki;
alter database pki character set utf8mb4 collate utf8mb4_general_ci;
use pki;

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
    `bio`        varchar(255) default '',
    `image_path` varchar(255)
);

# v2.0
create table if not exists system_api_index
(
    `system_index`  int primary key, # framework api index
    `system_api`    varchar(255) unique                 not null,
    `register_date` timestamp default CURRENT_TIMESTAMP not null
);

create table if not exists system_user
(
    `user_index`   int auto_increment primary key,
    `system_index` int,

    constraint system_api_user_fk
        foreign key (`system_index`) references system_api_index (`system_index`)
);


create table if not exists user_key
(
    `system_index` int          not null,
    `user_index`   int          not null,
    `public_key`   varchar(255) not null,
    `private_key`  varchar(255) not null,

    constraint user_pk primary key (`system_index`, `user_index`),
    constraint system_api_user_key_fk
        foreign key (`system_index`) references system_api_index (`system_index`)

);

create table if not exists user_log
(
    `user_index`   int                                 not null,
    `system_index` int                                 not null, # generate from framework api
    `time`         timestamp default CURRENT_TIMESTAMP not null,
    `ip`           varchar(30)                         not null,
    `device`       varchar(255)                        not null,
    `message`      varchar(255)                        not null,

    constraint user_system_index
        primary key (`user_index`, `system_index`),
    constraint system_api_user_log_fk
        foreign key (`system_index`) references system_api_index (`system_index`) on delete cascade

);