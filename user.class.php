<?php
namespace adistoe\UserSystem;

use PDO;

class User
{
    private $db;

    // Database tables - can be renamed if needed (only the value)
    private $dbTables = array(
        'user' => 'user'
    );

    // Salt for string hashes
    private $hashSalt = 'd22BNFXfOD9Permissions;6jQrFaFJ48*5C:KiNNZ5XQm!Svq';

    // Set to true if the permissions class is used or false if not
    private $usePermissions = false;

    /**
     * Constructor
     * Initializes the class
     *
     * @param object $db Database object
     */
    public function __construct($db)
    {
        $this->db = $db;
    }

    /**
     * Activate user
     *
     * @param string $username Username of the user to activate
     * @param string $token Token of the user to activate
     *
     * @return boolean Returns if the user was activated
     */
    public function activateUser($username, $token)
    {
        $userinfo = $this->getUserinfo($username);

        if ($userinfo['active'] == 0 && $userinfo['token'] == $token) {
            $stmt = $this->db->prepare('
                UPDATE ' . $this->dbTables['user'] . ' SET
                    active = 1,
                    token = NULL
                WHERE
                    UID = :UID
            ');

            $stmt->bindParam(':UID', $userinfo['UID']);
            $stmt->execute();

            if ($stmt->rowCount() > 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add new user
     *
     * @param string $username Username for the new user
     * @param string $password Password for the new user
     * @param string $passwordCheck Repeated password to compare with $password
     * @param string $firstname Firstname for the new user
     * @param string $lastname Lastname for the new user
     * @param string $address Address for the new user
     * @param int $zip ZIP for the new user
     * @param string $city City for the new user
     * @param string $country Country for the new user
     * @param string $phone Phone for the new user
     * @param string $mail Mail for the new user
     * @param boolean $active Specifies if the user should be active
     *
     * @return boolean Returns if the user was added
     */
    public function addUser(
        $username,
        $password,
        $passwordCheck,
        $firstname = '',
        $lastname = '',
        $address = '',
        $zip = '',
        $city = '',
        $country = '',
        $phone = '',
        $mail = '',
        $active = false
    ) {
        // Check if username and password are given
        if ($username == '' ||
            $password == '' ||
            $password != $passwordCheck
        ) {
            return false;
        }

        // Username must not be numeric
        if (ctype_digit($username)) {
            return false;
        }

        // Hash password
        $password = $this->hashString($password);

        // Correct encoding where necessary
        $username = htmlspecialchars($username);
        $firstname = htmlspecialchars($firstname);
        $lastname = htmlspecialchars($lastname);
        $address = htmlspecialchars($address);
        $city = htmlspecialchars($city);
        $country = htmlspecialchars($country);

        // Prevent from creating two users with the same username
        $stmt = $this->db->prepare('
            SELECT
                COUNT(UID) AS count
            FROM ' . $this->dbTables['user'] . '
            WHERE
                username = :username
        ');

        $stmt->bindParam(':username', $username);
        $stmt->execute();

        if ($row = $stmt->fetchObject()) {
            if ($row->count > 0) {
                return false;
            }
        }

        $token = null;

        if (!$active) {
            $token = $this->generateToken($username . $mail);
        }

        if ($active) {
            $active = 1;
        } else {
            $active = 0;
        }

        // Insert new user
        $stmt = $this->db->prepare('
            INSERT INTO ' . $this->dbTables['user'] . '(
                username,
                password,
                firstname,
                lastname,
                address,
                zip,
                city,
                country,
                phone,
                mail,
                active,
                token
            ) VALUES(
                :username,
                :password,
                :firstname,
                :lastname,
                :address,
                :zip,
                :city,
                :country,
                :phone,
                :mail,
                :active,
                :token
            )
        ');

        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $password);
        $stmt->bindParam(':firstname', $firstname);
        $stmt->bindParam(':lastname', $lastname);
        $stmt->bindParam(':address', $address);
        $stmt->bindParam(':zip', $zip);
        $stmt->bindParam(':city', $city);
        $stmt->bindParam(':country', $country);
        $stmt->bindParam(':phone', $phone);
        $stmt->bindParam(':mail', $mail);
        $stmt->bindParam(':active', $active);
        $stmt->bindParam(':token', $token);
        $stmt->execute();

        // Check if there was an insertion
        if ($stmt->rowCount() > 0) {
            return true;
        }

        return false;
    }

    /**
     * Check if the login data is correct
     *
     * @param string $user Username
     * @param string $pass Password
     * @param boolean $isHashed Hash state of the password
     *
     * @return mixed Returns false if login is incorrect, else returns userID
     */
    private function checkLogin($user, $pass, $isHashed = false)
    {
        if (!$isHashed) {
            $pass = $this->hashString($pass);
        }

        $stmt = $this->db->prepare('
            SELECT
                UID
            FROM ' . $this->dbTables['user'] . '
            WHERE
                username = :user AND
                password = :pass
        ');

        $stmt->bindParam(':user', $user);
        $stmt->bindParam(':pass', $pass);
        $stmt->execute();

        // Check if the user data is valid
        if ($row = $stmt->fetchObject()) {
            return $row->UID;
        }
        
        return false;
    }

    /**
     * Create database tables
     */
    public function databaseCreateTables()
    {
        $stmt = $this->db->prepare('
            CREATE TABLE `' . $this->dbTables['user'] . '` (
                `UID` INT NOT NULL AUTO_INCREMENT,
                `username` TEXT NOT NULL,
                `password` TEXT NOT NULL,
                `firstname` TEXT,
                `lastname` TEXT,
                `address` TEXT,
                `zip` INT,
                `city` TEXT,
                `country` TEXT,
                `phone` TEXT,
                `mail` TEXT,
                `active` TINYINT(1) NOT NULL DEFAULT 0,
                `token` TEXT,
                `created` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `updated` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (`UID`)
            ) DEFAULT CHARSET=utf8
        ');

        if ($stmt->execute()) {
            return true;
        }

        return false;
    }

    /**
     * Check if the login data is correct
     *
     * @param string $id ID for the user to delete
     *
     * @return boolean Returns if the user was deleted
     */
    public function deleteUser($id)
    {
        // Delete user
        if ($usePermissions) {
            $stmt = $this->db->prepare('
                DELETE
                    u,
                    ug
                FROM ' . $this->dbTables['user'] . ' AS u
                    LEFT JOIN user_groups AS ug
                        ON u.UID = ug.UID
                WHERE
                    u.UID = :UID
            ');
        } else {
            $stmt = $this->db->prepare('
                DELETE FROM
                    ' . $this->dbTables['user'] . '
                WHERE
                    UID = :UID
            ');
        }

        $stmt->bindParam(':UID', $id);
        $stmt->execute();

        // Check if there was a deletion
        if ($stmt->rowCount() > 0) {
            return true;
        }

        return false;
    }

    /**
     * Edit user
     *
     * @param string $id ID for the user to edit
     * @param string $username Username for the user to edit
     * @param string $password Password for the user to edit
     * @param string $passwordCheck Repeated password to compare with $password
     * @param string $firstname Firstname for the user to edit
     * @param string $lastname Lastname for the user to edit
     * @param string $address Address for the user to edit
     * @param int $zip ZIP for the user to edit
     * @param string $city City for the user to edit
     * @param string $country Country for the user to edit
     * @param string $phone Phone for the user to edit
     * @param string $mail Mail for the user to edit
     * @param boolean $active State of the user to edit
     *
     * @return boolean Returns if the user was edited
     */
    public function editUser(
        $id,
        $username,
        $password,
        $passwordCheck,
        $firstname,
        $lastname,
        $address,
        $zip,
        $city,
        $country,
        $phone,
        $mail,
        $active
    ) {
        if ($id == '' ||
            $username == '' ||
            $password == '' ||
            $password != $passwordCheck
        ) {
            return false;
        }

        // Username must not be numeric
        if (ctype_digit($username)) {
            return false;
        }

        // Hash password
        if ($password != '') {
            $password = $this->hashString($password);
        }

        // Correct encoding where necessary
        $username = htmlspecialchars($username);
        $firstname = htmlspecialchars($firstname);
        $lastname = htmlspecialchars($lastname);
        $address = htmlspecialchars($address);
        $city = htmlspecialchars($city);
        $country = htmlspecialchars($country);

        // Prevent from creating two users with the same username
        $stmt = $this->db->prepare('
            SELECT
                COUNT(UID) AS count
            FROM ' . $this->dbTables['user'] . '
            WHERE
                UID <> :UID AND
                username = :username
        ');

        $stmt->bindParam(':UID', $id);
        $stmt->bindParam(':username', $username);
        $stmt->execute();

        if ($row = $stmt->fetchObject()) {
            if ($row->count > 0) {
                return false;
            }
        }

        // Edit user
        $stmt = $this->db->prepare('
            UPDATE ' . $this->dbTables['user'] . ' SET
                username = :username,
                ' . ($password != '' ? 'password = :password,' : '') . '
                firstname = :firstname,
                lastname = :lastname,
                address = :address,
                zip = :zip,
                city = :city,
                country = :country,
                phone = :phone,
                mail = :mail,
                active = :active
            WHERE
                UID = :UID
        ');

        if ($password != '') {
            $stmt->bindParam(':password', $password);
        }

        $stmt->bindParam(':UID', $id);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':firstname', $firstname);
        $stmt->bindParam(':lastname', $lastname);
        $stmt->bindParam(':address', $address);
        $stmt->bindParam(':zip', $zip);
        $stmt->bindParam(':city', $city);
        $stmt->bindParam(':country', $country);
        $stmt->bindParam(':phone', $phone);
        $stmt->bindParam(':mail', $mail);
        $stmt->bindParam(':active', $active);

        if ($stmt->execute()) {
            return true;
        }

        return false;
    }

    /**
     * Generate token
     *
     * @param string $value - Value to use for the token generation
     *
     * @return string Returns generated token hashed
     */
    public function generateToken($value = '')
    {
        if ($value == '') {
            $value = time();
        }

        $firstRandomNumber = rand(0, 999999);
        $secondRandomNumber =  rand(0, 999999);

        $token = $this->hashString($firstRandomNumber . $value . $secondRandomNumber);

        return $token;
    }

    /**
     * Get user information
     *
     * @param int $user - ID or username of the user to get the info from
     *
     * @return mixed Returns false on error, else returns userinfo
     */
    public function getUserinfo($user)
    {
        // Get user by UID as default
        $column = 'UID';

        // If $user is not an integer, get user by username
        if (!ctype_digit($user)) {
            $column = 'username';
        }

        $stmt = $this->db->prepare("
            SELECT
                UID,
                username,
                password,
                firstname,
                lastname,
                address,
                zip,
                city,
                country,
                phone,
                mail,
                active,
                DATE_FORMAT(created, '%d.%m.%Y') AS created,
                DATE_FORMAT(updated, '%d.%m.%Y') AS updated
            FROM " . $this->dbTables['user'] . "
            WHERE
                $column = :user
        ");

        $stmt->bindParam(':user', $user);
        $stmt->execute();

        if ($userinfo = $stmt->fetch(PDO::FETCH_ASSOC)) {
            return $userinfo;
        }

        return false;
    }

    /**
     * Get userlist
     *
     * @param string $orderColumn Order results by given column
     * @param string $orderDirection Order results in given direction
     * @param string $limit Show only given amount of records
     *
     * @return string[] Returns userlist
     */
    public function getUsers(
        $orderColumn = 'UID',
        $orderDirection = 'ASC',
        $limit = ''
    ) {
        $limit = ($limit != '' ? 'LIMIT ' . $limit : '');
        $users = $this->db->query("
            SELECT
                UID,
                username,
                firstname,
                lastname,
                address,
                zip,
                city,
                country,
                phone,
                mail,
                active,
                DATE_FORMAT(created, '%d.%m.%Y') AS created,
                DATE_FORMAT(updated, '%d.%m.%Y') AS updated
            FROM " . $this->dbTables['user'] . "
            ORDER BY
                $orderColumn $orderDirection
            $limit
        ");

        $userlist = array();

        foreach ($users as $user) {
            $userlist[$user['UID']] = $user;
        }

        return $userlist;
    }

    /**
     * Hash string
     *
     * @param string $str String to hash
     */
    private function hashString($str)
    {
        $str = hash('sha512', $this->hashSalt . $str);

        return $str;
    }

    /**
     * Check if the user is logged in
     *
     * @param string $user Username
     * @param string $pass Password
     * @param boolean $isHashed Hash state of the password
     *
     * @return mixed Returns false if login is incorrect, else returns true
     */
    public function isLoggedIn($user, $pass, $isHashed = true)
    {
        if (!$this->checkLogin($user, $pass, $isHashed)) {
            return false;
        }

        return true;
    }

    /**
     * Login user
     *
     * @param string $user Username
     * @param string $pass Password
     *
     * @return mixed Returns false on error, else returns userinfo
     */
    public function login($user, $pass)
    {
        // Check if the credentials are correct
        if ($uid = $this->checkLogin($user, $pass)) {
            // Get userinfo
            if ($userinfo = $this->getUserinfo($uid)) {
                // Check if the user is active
                if ($userinfo['active']) {
                    return $userinfo;
                }
            }
        }

        return false;
    }

    /**
     * Register new user
     *
     * @param string $username Username for the new user
     * @param string $password Password for the new user
     * @param string $passwordCheck Repeated password to compare with $password
     * @param string $firstname Firstname for the new user
     * @param string $lastname Lastname for the new user
     * @param string $address Address for the new user
     * @param int $zip ZIP for the new user
     * @param string $city City for the new user
     * @param string $country Country for the new user
     * @param string $phone Phone for the new user
     * @param string $mail Mail for the new user
     *
     * @return boolean Returns if the user was added
     */
    public function register(
        $username,
        $password,
        $passwordCheck,
        $firstname = '',
        $lastname = '',
        $address = '',
        $zip = '',
        $city = '',
        $country = '',
        $phone = '',
        $mail = ''
    ) {
        if ($this->addUser(
            $username,
            $password,
            $passwordCheck,
            $firstname,
            $lastname,
            $address,
            $zip,
            $city,
            $country,
            $phone,
            $mail,
            false
        )) {
            return true;
        }

        return false;
    }
}
