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

create table if not exists system_api_index
(
    `system_id`     int auto_increment primary key, # framework api index
    `system_api`    varchar(255) unique                 not null,
    `register_date` timestamp default CURRENT_TIMESTAMP not null,
    `public_key`    mediumtext                          not null,
    `private_key`   mediumtext                          not null
);

create table if not exists system_user
(
    `system_user_id` int auto_increment primary key,
    `system_id`      int,
    `username`       varchar(255) unique not null,
    `password`       varchar(255)        not null,

    constraint system_api_user_fk
        foreign key (`system_id`) references system_api_index (`system_id`)
);

create table if not exists user_key
(
    `system_id`   int        not null,
    `user_id`     int        not null,
    `public_key`  mediumtext not null,
    `private_key` mediumtext not null,

    constraint user_pk primary key (`system_id`, `user_id`),
    constraint system_api_user_key_fk
        foreign key (`system_id`) references system_api_index (`system_id`)

);

create table if not exists user_log
(
    `user_id`   int                                 not null,
    `system_id` int                                 not null, # generate from framework api
    `time`      timestamp default CURRENT_TIMESTAMP not null,
    `ip`        varchar(30)                         not null,
    `device`    varchar(255)                        not null,
    `message`   varchar(255)                        not null,

    constraint user_system_index
        primary key (`user_id`, `system_id`),
    constraint system_api_user_log_fk
        foreign key (`system_id`) references system_api_index (`system_id`) on delete cascade

);

create table if not exists user_token
(
    `token_id`  int primary key auto_increment      not null,
    `user_id`   int                                 not null,
    `system_id` int                                 not null,
    `init_date` timestamp default CURRENT_TIMESTAMP not null,
    `validBy`  timestamp                           not null,
    `token`     text,

    constraint user_token_user_fk
        foreign key (`system_id`, `user_id`) references user_key (`system_id`, `user_id`) on delete cascade


);

create table if not exists qrcode_status
(
    `token_id` int,
    `nonce`    int           not null,
    `sym_key`  text          not null,
    `status`   int default 0 not null,

    constraint qrcode_token_fk
        foreign key (`token_id`) references user_token (`token_id`) on delete cascade
);

# procedure for status update
create procedure out_of_date()
begin
    delete
    from user_token
    where timestampdiff(SECOND, `validBy`, CURRENT_TIMESTAMP) <= 0;
end;

# event for status update
create definer = root@localhost event event_auto_cancel_order
    on schedule
        every '1' DAY
            starts '2019-06-27 00:00:00'
    on completion preserve
    enable
    do
    call out_of_date();