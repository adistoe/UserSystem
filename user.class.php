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

    // Stuff for hashing
    private $hashPepper = 'd22BNFXfOD9Permissions;6jQrFaFJ48*5C:KiNNZ5XQm!Svq';
    private $hashOptions = [
        'cost' => 10
    ];

    // Set to true if the permissions class is used or false if not
    private $usePermissions = true;

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
     * @param string $mail Mail for the new user
     * @param string $firstname Firstname for the new user
     * @param string $lastname Lastname for the new user
     * @param string $address Address for the new user
     * @param int $zip ZIP for the new user
     * @param string $city City for the new user
     * @param string $country Country for the new user
     * @param string $phone Phone for the new user
     * @param boolean $active Specifies if the user should be active
     *
     * @return boolean Returns if the user was added
     */
    public function addUser(
        $username,
        $password,
        $passwordCheck,
        $mail = '',
        $firstname = '',
        $lastname = '',
        $address = '',
        $zip = '',
        $city = '',
        $country = '',
        $phone = '',
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
        $password = password_hash($password . $this->hashPepper, PASSWORD_DEFAULT, $this->hashOptions);

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

        // Get current time
        $now = date('Y-m-d H:i:s', time());

        // Insert new user
        $stmt = $this->db->prepare('
            INSERT INTO ' . $this->dbTables['user'] . '(
                username,
                password,
                mail,
                firstname,
                lastname,
                address,
                zip,
                city,
                country,
                phone,
                active,
                token,
                created,
                updated
            ) VALUES(
                :username,
                :password,
                :mail,
                :firstname,
                :lastname,
                :address,
                :zip,
                :city,
                :country,
                :phone,
                :active,
                :token,
                :now,
                :now
            )
        ');

        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $password);
        $stmt->bindParam(':mail', $mail);
        $stmt->bindParam(':firstname', $firstname);
        $stmt->bindParam(':lastname', $lastname);
        $stmt->bindParam(':address', $address);
        $stmt->bindParam(':zip', $zip);
        $stmt->bindParam(':city', $city);
        $stmt->bindParam(':country', $country);
        $stmt->bindParam(':phone', $phone);
        $stmt->bindParam(':active', $active);
        $stmt->bindParam(':token', $token);
        $stmt->bindParam(':now', $now);
        $stmt->execute();

        // Check if there was an insertion
        if ($stmt->rowCount() > 0) {
            return true;
        }

        return false;
    }

    /**
     * Create database tables
     */
    public function databaseCreateTables()
    {
        $stmt = $this->db->prepare('
            CREATE TABLE ' . $this->dbTables['user'] . ' (
                UID INT UNSIGNED NOT NULL AUTO_INCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                mail TEXT,
                firstname TEXT,
                lastname TEXT,
                address TEXT,
                zip INT(5) UNSIGNED,
                city TEXT,
                country TEXT,
                phone TEXT,
                active TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
                token TEXT,
                created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (UID)
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
        if ($this->usePermissions) {
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
     * @param string $mail Mail for the user to edit
     * @param string $firstname Firstname for the user to edit
     * @param string $lastname Lastname for the user to edit
     * @param string $address Address for the user to edit
     * @param int $zip ZIP for the user to edit
     * @param string $city City for the user to edit
     * @param string $country Country for the user to edit
     * @param string $phone Phone for the user to edit
     * @param boolean $active State of the user to edit
     *
     * @return boolean Returns if the user was edited
     */
    public function editUser(
        $id,
        $username,
        $password,
        $passwordCheck,
        $mail = '',
        $firstname = '',
        $lastname = '',
        $address = '',
        $zip = '',
        $city = '',
        $country = '',
        $phone = '',
        $active = false
    ) {
        if ($id == '' ||
            $username == '' ||
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
            $password = password_hash($password . $this->hashPepper, PASSWORD_DEFAULT, $this->hashOptions);
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

        // Get current time
        $now = date('Y-m-d H:i:s', time());

        // Edit user
        $stmt = $this->db->prepare('
            UPDATE ' . $this->dbTables['user'] . ' SET
                username = :username,
                ' . ($password != '' ? 'password = :password,' : '') . '
                mail = :mail,
                firstname = :firstname,
                lastname = :lastname,
                address = :address,
                zip = :zip,
                city = :city,
                country = :country,
                phone = :phone,
                active = :active,
                updated = :now
            WHERE
                UID = :UID
        ');

        if ($password != '') {
            $stmt->bindParam(':password', $password);
        }

        $stmt->bindParam(':UID', $id);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':mail', $mail);
        $stmt->bindParam(':firstname', $firstname);
        $stmt->bindParam(':lastname', $lastname);
        $stmt->bindParam(':address', $address);
        $stmt->bindParam(':zip', $zip);
        $stmt->bindParam(':city', $city);
        $stmt->bindParam(':country', $country);
        $stmt->bindParam(':phone', $phone);
        $stmt->bindParam(':active', $active);
        $stmt->bindParam(':now', $now);

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
     * Get user ID of the stayin token if exists
     *
     * @param string $token Token to check
     *
     * @return int Returns user id which is associated to the stayin token
     */
    private function getStayLoggedIn($token)
    {
        $token = $this->hashString($token);
        $stmt = $this->db->prepare(
            'SELECT
                `UID`
            FROM
                user_stayin
            WHERE
                token = :token'
        );

        $stmt->bindParam('token', $token);
        $stmt->execute();

        if ($stayin = $stmt->fetch(PDO::FETCH_ASSOC)['UID']) {
            return $stayin;
        }

        return false;
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
                mail,
                firstname,
                lastname,
                address,
                zip,
                city,
                country,
                phone,
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
                mail,
                firstname,
                lastname,
                address,
                zip,
                city,
                country,
                phone,
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
        $str = hash('sha512', $this->hashPepper . $str);

        return $str;
    }

    /**
     * Login user
     *
     * @param string $user Username
     * @param string $pass Password
     * @param boolean $stayin Specifies if the user should stay logged in
     *
     * @return mixed Returns false on error, else returns userinfo
     */
    public function login($user, $pass, $stayin = false)
    {
        $stmt = $this->db->prepare('
            SELECT
                UID,
                password
            FROM
                ' . $this->dbTables['user'] . '
            WHERE
                username = :user
        ');

        $stmt->bindParam(':user', $user);
        $stmt->execute();

        // Check if the user data is valid
        if ($row = $stmt->fetchObject()) {
            if (password_verify($pass . $this->hashPepper, $row->password)) {
                // Check if the password hash is up to date else update it
                if (password_needs_rehash($row->password, PASSWORD_DEFAULT, $this->hashOptions)) {
                    $newPass = password_hash($pass . $this->hashPepper, PASSWORD_DEFAULT, $this->hashOptions);
                    $stmt = $this->db->prepare(
                        'UPDATE
                            ' . $this->dbTables['user'] . '
                        SET
                            password = :password
                        WHERE
                            UID = :userID'
                    );

                    $stmt->bindParam('password', $newPass);
                    $stmt->bindParam('userID', $row->UID);
                    $stmt->execute();
                }

                // Get userinfo
                if ($userinfo = $this->getUserinfo($row->UID)) {
                    // Check if the user is active
                    if ($userinfo['active']) {
                        if ($stayin && !$this->setStayLoggedIn($row->UID)) {
                            return false;
                        }
    
                        return $userinfo;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Logout user
     *
     * @param int $uid ID of the user to logout
     *
     * @return mixed Returns false on error, else returns true
     */
    public function logout($uid)
    {
        $token = null;

        if (isset($_COOKIE['stayin'])) {
            $token = $_COOKIE['stayin'];
        }

        $hashedToken = $this->hashString($token);
        $stmt = $this->db->prepare(
            'DELETE FROM
                user_stayin
            WHERE
                `UID` = :userID AND
                token = :token'
        );

        $stmt->bindParam('userID', $uid);
        $stmt->bindParam('token', $hashedToken);
        
        if ($stmt->execute()) {
            // Delete cookie
            setcookie(
                'stayin',
                $token,
                time() - 1,
                '/'
            );
            return true;
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
        $mail = '',
        $firstname = '',
        $lastname = '',
        $address = '',
        $zip = '',
        $city = '',
        $country = '',
        $phone = ''
    ) {
        if ($this->addUser(
            $username,
            $password,
            $passwordCheck,
            $mail,
            $firstname,
            $lastname,
            $address,
            $zip,
            $city,
            $country,
            $phone,
            false
        )) {
            return true;
        }

        return false;
    }

    /**
     * Set "stay logged in" state for the user
     *
     * @param int $uid User ID
     * @param string $oldToken Token to get the entry to update if it already exists
     */
    private function setStayLoggedIn($uid, $oldToken = false)
    {
        if ($oldToken) {
            $query = 'UPDATE
                user_stayin
                    SET
                        token = :token,
                        created = :now
                    WHERE
                        `UID` = :userID AND
                        token = :oldToken';
        } else {
            $query = 'INSERT INTO
                user_stayin (
                    `UID`,
                    token,
                    created
                )
            VALUES (
                :userID,
                :token,
                :now
            )';
        }

        // Get current time
        $now = date('Y-m-d H:i:s', time());

        // Generate and hash token
        $token = $uid . $this->generateToken($now);
        $hashedToken = $this->hashString($token);

        // Add "stay logged in" entry
        $stmt = $this->db->prepare($query);

        $stmt->bindParam('userID', $uid);
        $stmt->bindParam('token', $hashedToken);
        $stmt->bindParam('now', $now);

        if ($oldToken) {
            // Hash the old token
            $oldToken = $this->hashString($oldToken);

            // Bind it
            $stmt->bindParam('oldToken', $oldToken);
        }

        if ($stmt->execute()) {
            // Set cookie
            setcookie(
                'stayin',
                $token,
                time() + 60 * 60 * 24 * 365,
                '/'
            );

            return true;
        }

        return false;
    }

    /**
     * Login user with stayin cookie
     *
     * @param string $token Stayin cookie token
     *
     * @return mixed Returns false on error, else returns userinfo
     */
    public function stayinLogin($token)
    {
        // Check if the stayin token exists
        if ($uid = $this->getStayLoggedIn($token)) {
            // Get userinfo
            if ($userinfo = $this->getUserinfo($uid)) {
                // Check if the user is active and if the stayin cookie could be set
                if ($userinfo['active'] && $this->setStayLoggedIn($uid, $token)) {
                    return $userinfo;
                }
            }
        }

        return false;
    }
}
