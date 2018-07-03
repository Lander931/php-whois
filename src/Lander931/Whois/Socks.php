<?php

namespace Lander931\Whois;


class Socks
{
    private $type;
    private $socket;
    private $status;
    private $socks_server = array();
    private $remote_server = array();
    private $error = array();
    private $bind_type;
    private $connection_timeout;
    private $stream_timeout;


    public function __construct($type, $ip, $port, $login = '', $pass = '', $connection_timeout = 60, $stream_timeout = 60)
    {
        $this->connection_timeout = $connection_timeout;
        $this->stream_timeout = $stream_timeout;

        $this->socket = fsockopen($ip, $port, $err, $errstr, $this->connection_timeout);

        stream_set_timeout($this->socket, 0, $this->stream_timeout * 1000000);
        $type = strtolower($type);
        $this->type = $type;
        if ($this->socket) {
            if (!($this->auth($type, $login, $pass))) {
                $this->close();
                return false;
            }
        } else {
            $this->close();
            return false;
        }
        return $this->socket;
    }

    private function auth($type, $login = '', $pass = '')
    {
        if ($type == 'socks5') {
            if (!($this->socks5_auth($login, $pass))) {
                $this->error = array('function' => 'auth', 'num' => 00);
                return false;
            }
        } elseif ($type == 'socks4' || $type == 'socks4a') {
            if (!($this->socket)) {
                $this->error = array('function' => 'auth', 'num' => 00);
                return false;
            }
        }
        return true;
    }

    private function socks5_auth($login, $pass)
    {
        $h = pack("H*", '05020002');
        $this->send($h);
        $l = $this->loop();
        $status = substr($l, 2, 2);
        if ($status == '00') {
            return true;
        } elseif ($status == '02') {
            $h = pack("H*", "01") . chr(strlen($login)) . $login . chr(strlen($pass)) . $pass;
            $this->send($h);
            $l = $this->loop();
            $status = substr($l, 2, 2);
            if ($status == '00') {
                return true;
            } else {
                return false;
            }
        }
    }

    public function connect($host, $port, $type = '')
    {
        if (!$type) {
            $type = $this->type;
        }
        if ($type == 'socks5') {
            $status = $this->socks5_connect($host, $port);
        } elseif ($type == 'socks4') {
            $status = $this->socks4_connect($host, $port);
        } elseif ($type == 'socks4a') {
            $status = $this->socks4a_connect($host, $port);
        }
        if (strlen($status) == 2) {
            $status = $this->error_socks_2_error_class($status);
            $this->error = array('function' => 'connect', 'num' => $status);
            return $status;
        }
        return true;
    }

    private function socks5_connect($host, $port)
    {
        $h = pack("H*", "05010003") . chr(strlen($host)) . $host . pack("n", $port);
        $this->send($h);
        $l = $this->loop();
        $status = substr($l, 2, 2);
        if ($status == '00') {
            return true;
        } else {
            return $status;
        }
    }

    private function socks4_connect($host, $port)
    {
        $h = pack("H*", "0401") . pack("n", $port) . pack("H*", dechex(ip2long(gethostbyname($host)))) . pack("H*", "00");
        $this->send($h);
        $l = $this->loop();
        $ver = substr($l, 0, 2);
        $status = strtolower(substr($l, 2, 2));
        if ($ver == 00) {
            if ($status == '5a') {
                return true;
            } else {
                if (!$status) {
                    $status = '00';
                }
                return $status;
            }
        } else {
            return '00';
        }
    }

    private function socks4a_connect($host, $port)
    {
        $h = pack("H*", "0401") . pack("n", $port) . pack("H*", '0000000' . rand(1, 9) . "00") . $host . pack("H*", "00");
        $this->send($h);
        $l = $this->loop();
        $ver = substr($l, 0, 2);
        $status = strtolower(substr($l, 2, 2));

        if ($ver == 00) {
            if ($status == '5a') {
                return true;
            } else {
                return $status;
            }
        } else {
            return 00;
        }
    }

    public function bind($host, $port, $type = '')
    {
        if (!$type) {
            $type = $this->type;
        }
        $this->bind_type = $type;
        if ($type == 'socks5') {
            $status = $this->socks5_bind($host, $port);
        } elseif ($type == 'socks4a') {
            $status = $this->socks4a_bind($host, $port);
        } else {
            return false;
        }

        if (!is_array($status)) {
            $status = $this->error_socks_2_error_class($status);
            $this->error = array('function' => 'bind', 'num' => $status);
            return $status;
        }
        return $this->socks_server;
    }

    private function socks5_bind($host, $port)
    {
        $h = pack("H*", '05020003') . chr(strlen($host)) . $host . pack("n", $port);
        $this->send($h);
        $l = $this->loop();
        $status = substr($l, 2, 2);
        if ($status == 0) {
            $l = substr($l, 6);
            $this->socks_server['type'] = (int)hexdec(substr($l, 0, 2));
            $this->socks_server['host'] = long2ip(hexdec(substr($l, 2, 8)));
            $this->socks_server['port'] = (int)hexdec(substr($l, 10, 4));
            $this->status = 2;
            return $this->socks_server;
        } else {
            return $status;
        }
    }

    private function socks4a_bind($host, $port)
    {
        $h = pack("H*", "0402") . pack("n", $port) . pack("H*", '0000000' . rand(1, 9) . "00") . $host . pack("H*", "00");
        $this->send($h);
        $l = $this->loop();
        $ver = substr($l, 0, 2);
        $status = strtolower(substr($l, 2, 2));
        if ($ver == 00) {
            if ($status == '5a') {
                $this->socks_server['type'] = 01;
                $this->socks_server['host'] = long2ip(hexdec(substr($l, 8, 8)));
                $this->socks_server['port'] = hexdec(substr($l, 4, 4));
                $this->status = 2;
                return $this->socks_server;
            } else {
                return $status;
            }
        }
    }

    public function send($dump)
    {
        if (is_resource($this->socket)) fwrite($this->socket, $dump);
    }

    private function status_rem_connect()
    {
        if ($this->status == 2) {
            if ($this->bind_type == 'socks5') {
                $status = $this->status_rem_connect_socks5();
            } elseif ($this->bind_type == 'socks4a') {
                $status = $this->status_rem_connect_socks4a();
            }

            if (!is_array($status)) {
                $status = $this->error_socks_2_error_class($status);
                $this->error = array('function' => 'status_rem_connect', 'num' => $status);
                return $status;
            }
            return $this->remote_server;
        } else {
            $this->error = array('function' => 'status_rem_connect', 'num' => '00');
            return '00';
        }
    }

    private function status_rem_connect_socks5()
    {
        $l = $this->loop();
        $status = substr($l, 2, 2);
        if ($status == '00') {
            $l = substr($l, 6);

            $this->remote_server['type'] = (int)hexdec(substr($l, 0, 2));
            $this->remote_server['host'] = long2ip(hexdec(substr($l, 2, 8)));
            $this->remote_server['port'] = (int)hexdec(substr($l, 10, 4));

            $this->status = 0;
            return $this->remote_server;
        } else {
            return $status;
        }
    }

    private function status_rem_connect_socks4a()
    {
        $l = $this->loop(8);
        $status = substr($l, 2, 2);
        if ($status == '5a') {
            $l = substr($l, 4);
            $this->remote_server['type'] = '01';
            $this->remote_server['host'] = long2ip(hexdec(substr($l, 4, 8)));
            $this->remote_server['port'] = (int)hexdec(substr($l, 0, 4));

            $this->status = 0;
            return $this->remote_server;
        } else {
            return $status;
        }
    }

    public function read($len = 0)
    {
        if ($this->status == 2 && $this->type != 'socks4') {
            $status = $this->status_rem_connect();
            if (is_numeric($status)) {
                return false;
            }
        }
        $dump = "";
        if ($len != 0) {
            $dump .= fread($this->socket, $len);
        } else {
            $s = microtime(true);
            while (is_resource($this->socket) && !feof($this->socket)) {
                if ((microtime(true) - $s) < $this->stream_timeout){
                    $dump .= fread($this->socket, 1024);
                } else {
                    break;
                }
            }
        }
        return $dump;
    }

    public function close()
    {
        if (is_resource($this->socket)) fclose($this->socket);
    }

    private function loop($size = 1024)
    {
        if (is_resource($this->socket)){
            return bin2hex(fread($this->socket, $size));
        } else {
            return '';
        }
    }

    private function error_socks_2_error_class($num_err)
    {
        switch ($num_err) {
            /* socks5 */
            case '01':
                return '01';
                break;
            case '02':
                return '02';
                break;
            case '03':
                return '03';
                break;
            case '04':
                return '04';
                break;
            case '05':
                return '05';
                break;
            case '06':
                return '06';
                break;
            case '07':
                return '07';
                break;
            case '08':
                return '08';
                break;
            /* socks4/socks4a */
            case '5b':
                return '09';
                break;
            case '5c':
                return '10';
                break;
            case '5d':
                return '11';
                break;
            /* All socks */
            default  :
                return '00';
                break;
        }
    }
}