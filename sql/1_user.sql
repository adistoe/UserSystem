START TRANSACTION;

--
-- Table structure for table `user`
--

CREATE TABLE `user` (
	`UID` INT NOT NULL AUTO_INCREMENT,
	`username` TEXT NOT NULL,
	`password` TEXT NOT NULL,
	`mail` TEXT,
	`firstname` TEXT,
	`lastname` TEXT,
	`address` TEXT,
	`zip` INT,
	`city` TEXT,
	`country` TEXT,
	`phone` TEXT,
	`active` TINYINT(1) NOT NULL DEFAULT 0,
	`token` TEXT,
	`created` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (`UID`)
) DEFAULT CHARSET=utf8;

COMMIT;
