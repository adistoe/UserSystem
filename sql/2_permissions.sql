START TRANSACTION;

--
-- Table structure for table `groups`
--

CREATE TABLE `groups` (
    `GID` INT NOT NULL AUTO_INCREMENT,
    `name` TEXT NOT NULL,
    PRIMARY KEY (`GID`)
) DEFAULT CHARSET=utf8;

--
-- Table structure for table `permissions`
--

CREATE TABLE `permissions` (
    `PID` INT NOT NULL AUTO_INCREMENT,
    `name` TEXT NOT NULL,
    `description` TEXT NOT NULL,
    PRIMARY KEY (`PID`)
) DEFAULT CHARSET=utf8;

--
-- Table structure for table `group_permissions`
--

CREATE TABLE `group_permissions` (
    `GID` INT NOT NULL,
    `PID` INT NOT NULL,
    PRIMARY KEY (`GID`, `PID`),
    CONSTRAINT `GP_FK_GID` FOREIGN KEY (`GID`) REFERENCES `groups` (`GID`),
    CONSTRAINT `GP_FK_PID` FOREIGN KEY (`PID`) REFERENCES `permissions` (`PID`)
) DEFAULT CHARSET=utf8;

--
-- Table structure for table `user_groups`
--

CREATE TABLE `user_groups` (
    `UID` INT NOT NULL,
    `GID` INT NOT NULL,
    PRIMARY KEY (`UID`, `GID`),
    CONSTRAINT `UG_FK_GID` FOREIGN KEY (`GID`) REFERENCES `groups` (`GID`)
) DEFAULT CHARSET=utf8;

COMMIT;