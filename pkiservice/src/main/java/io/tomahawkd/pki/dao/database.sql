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

# v2.0
create table if not exists system_api_index
(
    `system_index`  int auto_increment primary key, # framework api index
    `system_api`    varchar(255) unique                 not null,
    `register_date` timestamp default CURRENT_TIMESTAMP not null
);

create table if not exists system_user
(
    `user_index`   int auto_increment primary key,
    `system_index` int,
    `username`     varchar(255) unique not null,
    `password`     varchar(255)        not null,

    constraint system_api_user_fk
        foreign key (`system_index`) references system_api_index (`system_index`)
);


create table if not exists user_key
(
    `system_index` int        not null,
    `user_index`   int        not null,
    `public_key`   mediumtext not null,
    `private_key`  mediumtext not null,

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