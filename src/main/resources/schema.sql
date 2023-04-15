set mode MySQL;

CREATE TABLE IF NOT EXISTS users (
    user_id bigint not null primary key auto_increment,
    username varchar(50) not null unique,
    password varchar(100),
    role varchar(100) default 'ROLE_USER'
);