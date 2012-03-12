
<?php

// courtesy dwilliams
// http://www.phpfreaks.com/forums/index.php?topic=347928.0

error_reporting(E_ALL);
set_time_limit(0);
ob_implicit_flush();
date_default_timezone_set('America/Chicago');

$master  = WebSocket('192.168.1.29', 12345);
$sockets = array($master);
$users   = array();

while(true)
{
	$changed = $sockets;
	socket_select($changed,$write=NULL,$except=NULL,NULL);
	foreach($changed as $socket)
	{
		if($socket == $master)
		{
			$client = socket_accept($master);
			if($client < 0)
			{
				server_log('socket_accept() failed', 2); 
				continue; 
			}
			else
			{ 
				connect($client); 
			}
		}
		else
		{
			$bytes = socket_recv($socket,$buffer,2048,0);
			if($bytes==0)
			{
				disconnect($socket);
			}
			else
			{	
				$user = getuserbysocket($socket);

				if(!$user->handshake)
				{
					dohandshake($user,$buffer);
				}
  		      else
  	  		   {
  	  		   	// Decode the WebSocket data and process accordingly
  	  		   	$data = hybi10Decode($buffer);
  	  		   	
  	  		   	if($data['type'] == 'text')
  	  		   	{
						process($user, $data['payload']); 
					}
					elseif($data['type'] == 'ping')
					{
						
					}
					elseif($data['type'] == 'pong')
					{
						
					}
					elseif($data['type'] == 'close')
					{
						
					}
				}
			}
		}
	}
}

//---------------------------------------------------------------
function server_log($msg, $sev = 1)
{
	echo '[' . date('G:i:s') . "] $msg\n";	
}

function process($user, $msg)
{
	server_log("Message received: ". $msg);
}

function send($client,$msg)
{
	server_log("> ".$msg, 1);
	$msg = hybi10Encode($msg, 'close');
	socket_write($client,$msg,strlen($msg));
}

function WebSocket($address,$port)
{
	$master=socket_create(AF_INET, SOCK_STREAM, SOL_TCP)     or die("socket_create() failed");
	socket_set_option($master, SOL_SOCKET, SO_REUSEADDR, 1)  or die("socket_option() failed");
	socket_bind($master, $address, $port)                    or die("socket_bind() failed");
	socket_listen($master,20)                                or die("socket_listen() failed");
	server_log('Server Started : ' . date('Y-m-d H:i:s'), 1);
	server_log("Master socket  : $master", 1);
	server_log("Listening on   : {$address}:{$port}", 1);
	return $master;
}

function connect($socket)
{
	global $sockets,$users;
	$user = new User();
	$user->id = uniqid();
	$user->socket = $socket;
	array_push($users,$user);
	array_push($sockets,$socket);
	server_log('New client connected', 1);
}

function disconnect($socket){
  global $sockets,$users;
  $found=null;
  $n=count($users);
  for($i=0;$i<$n;$i++){
    if($users[$i]->socket==$socket){ $found=$i; break; }
  }
  if(!is_null($found)){ array_splice($users,$found,1); }
  $index = array_search($socket,$sockets);
  socket_close($socket);
  console($socket." DISCONNECTED!");
  if($index>=0){ array_splice($sockets,$index,1); }
}

function dohandshake($user, $buffer)
{
	server_log('Requesting handshake...', 1);
	
	// Determine which version of the WebSocket protocol the client is using
	if(preg_match("/Sec-WebSocket-Version: (.*)\r\n/ ", $buffer, $match))
		$version = $match[1];
	else 
		return false;
		
	if($version == 8)
	{
		// Extract header variables
		if(preg_match("/GET (.*) HTTP/"   ,$buffer,$match)){ $r=$match[1]; }
		if(preg_match("/Host: (.*)\r\n/"  ,$buffer,$match)){ $h=$match[1]; }
		if(preg_match("/Sec-WebSocket-Origin: (.*)\r\n/",$buffer,$match)){ $o=$match[1]; }
		if(preg_match("/Sec-WebSocket-Key: (.*)\r\n/",$buffer,$match)){ $k = $match[1]; }

		// Generate our Socket-Accept key based on the IETF specifications
		$accept_key = $k . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
		$accept_key = sha1($accept_key, true);
		$accept_key = base64_encode($accept_key);
		
		$upgrade =	"HTTP/1.1 101 Switching Protocols\r\n" .
						"Upgrade: websocket\r\n" .
						"Connection: Upgrade\r\n" .
						"Sec-WebSocket-Accept: $accept_key\r\n\r\n";
						
		socket_write($user->socket, $upgrade, strlen($upgrade));
		$user->handshake = true;
		return true;
	}
	else 
	{
		server_log("Client is trying to use an unsupported WebSocket protocol ({$version})", 1);
		return false;
	}
}

function getuserbysocket($socket)
{
	global $users;
	$found = null;
	foreach($users as $user)
	{
		if($user->socket==$socket)
		{
			$found = $user; 
			break; 
		}
	}
  return $found;
}

function hybi10Encode($payload, $type = 'text', $masked = true)
{
	$frameHead = array();
	$frame = '';
	$payloadLength = strlen($payload);

	switch($type)
	{
		case 'text':
		// first byte indicates FIN, Text-Frame (10000001):
		$frameHead[0] = 129;
		break;

		case 'close':
		// first byte indicates FIN, Close Frame(10001000):
		$frameHead[0] = 136;
		break;

		case 'ping':
		// first byte indicates FIN, Ping frame (10001001):
		$frameHead[0] = 137;
		break;

		case 'pong':
		// first byte indicates FIN, Pong frame (10001010):
		$frameHead[0] = 138;
		break;
	}

	// set mask and payload length (using 1, 3 or 9 bytes)
	if($payloadLength > 65535)
	{
		$payloadLengthBin = str_split(sprintf('%064b', $payloadLength), 8);
		$frameHead[1] = ($masked === true) ? 255 : 127;
		for($i = 0; $i < 8; $i++)
		{
			$frameHead[$i+2] = bindec($payloadLengthBin[$i]);
		}

		// most significant bit MUST be 0 (close connection if frame too big)
		if($frameHead[2] > 127)
		{
			$this->close(1004);
			return false;
		}
	}
	elseif($payloadLength > 125)
	{
		$payloadLengthBin = str_split(sprintf('%016b', $payloadLength), 8);
		$frameHead[1] = ($masked === true) ? 254 : 126;
		$frameHead[2] = bindec($payloadLengthBin[0]);
		$frameHead[3] = bindec($payloadLengthBin[1]);
	}
	else
	{
		$frameHead[1] = ($masked === true) ? $payloadLength + 128 : $payloadLength;
	}

	// convert frame-head to string:
	foreach(array_keys($frameHead) as $i)
	{
		$frameHead[$i] = chr($frameHead[$i]);
	}

	if($masked === true)
	{
		// generate a random mask:
		$mask = array();
		for($i = 0; $i < 4; $i++)
		{
			$mask[$i] = chr(rand(0, 255));
		}

		$frameHead = array_merge($frameHead, $mask);
	}
	$frame = implode('', $frameHead);

	// append payload to frame:
	$framePayload = array();
	for($i = 0; $i < $payloadLength; $i++)
	{
		$frame .= ($masked === true) ? $payload[$i] ^ $mask[$i % 4] : $payload[$i];
	}

	return $frame;
}

function hybi10Decode($data)
{
	$payloadLength = '';
	$mask = '';
	$unmaskedPayload = '';
	$decodedData = array();

	// estimate frame type:
	$firstByteBinary = sprintf('%08b', ord($data[0]));
	$secondByteBinary = sprintf('%08b', ord($data[1]));
	$opcode = bindec(substr($firstByteBinary, 4, 4));
	$isMasked = ($secondByteBinary[0] == '1') ? true : false;
	$payloadLength = ord($data[1]) & 127;

	// close connection if unmasked frame is received:
	if($isMasked === false)
	{
		$this->close(1002);
	}

	switch($opcode)
	{
		// text frame:
		case 1:
		$decodedData['type'] = 'text';
		break;

		// connection close frame:
		case 8:
		$decodedData['type'] = 'close';
		break;

		// ping frame:
		case 9:
		$decodedData['type'] = 'ping';
		break;

		// pong frame:
		case 10:
		$decodedData['type'] = 'pong';
		break;

		default:
		// Close connection on unknown opcode:
		$this->close(1003);
		break;
	}

	if($payloadLength === 126)
	{
		$mask = substr($data, 4, 4);
		$payloadOffset = 8;
	}
	elseif($payloadLength === 127)
	{
		$mask = substr($data, 10, 4);
		$payloadOffset = 14;
	}
	else
	{
		$mask = substr($data, 2, 4);
		$payloadOffset = 6;
	}

	$dataLength = strlen($data);

	if($isMasked === true)
	{
		for($i = $payloadOffset; $i < $dataLength; $i++)
		{
			$j = $i - $payloadOffset;
			$unmaskedPayload .= $data[$i] ^ $mask[$j % 4];
		}
		$decodedData['payload'] = $unmaskedPayload;
	}
	else
	{
		$payloadOffset = $payloadOffset - 4;
		$decodedData['payload'] = substr($data, $payloadOffset);
	}

	return $decodedData;
}

class User{
  var $id;
  var $socket;
  var $handshake;
}


