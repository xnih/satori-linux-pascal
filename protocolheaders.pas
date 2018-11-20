unit ProtocolHeaders;

//chunks by Bogdan Calin
//most updated by Eric Kollmann

interface

uses
  classes, sockets;

// some constants
const
 Max_Packet         = 2048;

  // IP header options
 _IP_TTL            = 0;
 _IP_TOS            = 1;
 _IP_ID             = 2;
 _IP_DONT_FRAGMENT  = 3;
 _IP_MORE_FRAGMENTS = 4;
 _IP_FRAGMENT       = 5;
 _IP_VER            = 6;

 //IP protocol types : taken straight from Winsock
 _IPPROTO_IP     =   0;             { dummy for IP }
 _IPPROTO_ICMP   =   1;             { control message protocol }
 _IPPROTO_IGMP   =   2;             { group management protocol }
 _IPPROTO_GGP    =   3;             { gateway^2 (deprecated) }
 _IPPROTO_TCP    =   6;             { tcp }
 _IPPROTO_PUP    =  12;             { pup }
 _IPPROTO_UDP    =  17;             { user datagram protocol }
 _IPPROTO_IDP    =  22;             { xns idp }
 _IPPROTO_IPV6   =  41;
 _IPPROTO_ICMPV6 =  58;
 _IPPROTO_ND     =  77;             { UNOFFICIAL net disk proto }
 _IPPROTO_OSPF   =  89;
 _IPPROTO_RAW    =  255;            { raw IP packet }
 _IPPROTO_MAX    =  256;

  IPV6_UNICAST_HOPS      = 8;  // ???
  IPV6_MULTICAST_IF      = 9;  // set/get IP multicast i/f
  IPV6_MULTICAST_HOPS    = 10; // set/get IP multicast ttl
  IPV6_MULTICAST_LOOP    = 11; // set/get IP multicast loopback
  IPV6_JOIN_GROUP        = 12; // add an IP group membership
  IPV6_LEAVE_GROUP       = 13; // drop an IP group membership


 // TCP header options
 _TCP_SEQ           = 0;
 _TCP_ACK           = 1;
 _TCP_WINDOW        = 2;
 _TCP_URGENT        = 3;

 // TCP Options
 // only a few of them (for now)
 _TCP_OPTION_END          = 0;  // E
 _TCP_OPTION_NOOP         = 1;  // N
 _TCP_OPTION_MAX_SEG_SIZE = 2;  // M
 _TCP_OPTION_WIN_SCALE    = 3;  // W
 _TCP_OPTION_SACK_OK      = 4;  // S
 _TCP_OPTION_SACK         = 5;  // K
 _TCP_OPTION_ECHO         = 6;  // E
 _TCP_OPTION_ECHO_REPLY   = 7;  // F
 _TCP_OPTION_TIMESTAMP    = 8;  // T
 _TCP_OPTION_POCP         = 9;  // P
 _TCP_OPTION_POSP         = 10; // R

{*** http://www.iana.org/assignments/tcp-parameters
Kind   Length   Meaning                           Reference
----   ------   -------------------------------   ---------
  0        -    End of Option List                 [RFC793]
  1        -    No-Operation                       [RFC793]
  2        4    Maximum Segment Size               [RFC793]
  3        3    WSOPT - Window Scale              [RFC1323]
  4        2    SACK Permitted                    [RFC2018]
  5        N    SACK                              [RFC2018]
  6        6    Echo (obsoleted by option 8)      [RFC1072]
  7        6    Echo Reply (obsoleted by option 8)[RFC1072]
  8       10    TSOPT - Time Stamp Option         [RFC1323]
  9        2    Partial Order Connection Permitted[RFC1693]
 10        3    Partial Order Service Profile     [RFC1693]
 11             CC                                [RFC1644]
 12             CC.NEW                            [RFC1644]
 13             CC.ECHO                           [RFC1644]
 14         3   TCP Alternate Checksum Request    [RFC1146]
 15         N   TCP Alternate Checksum Data       [RFC1146]
 16             Skeeter                           [Knowles]
 17             Bubba                             [Knowles]
 18         3   Trailer Checksum Option    [Subbu & Monroe]
 19        18   MD5 Signature Option              [RFC2385]
 20             SCPS Capabilities                   [Scott]
 21		Selective Negative Acknowledgements [Scott]
 22		Record Boundaries                   [Scott]
 23		Corruption experienced              [Scott]
 24		SNAP				 [Sukonnik]
 25		Unassigned (released 12/18/00)
 26             TCP Compression Filter           [Bellovin]
 27          8  Quick-Start Response              [RFC4782]
 28-252         Unassigned
 253         N  RFC3692-style Experiment 1 (*)    [RFC4727]
 254         N  RFC3692-style Experiment 2 (*)    [RFC4727]
 ***}


 // IP TOS(Type of service) related
 _IP_TOS_ROUTINE        = 0;
 _IP_TOS_PRIORITY       = 1;
 _IP_TOS_IMMEDIATE      = 2;
 _IP_TOS_FLASH          = 3;
 _IP_TOS_FLASH_OVERRIDE = 4;
 _IP_TOS_CRITIC_ECP     = 5;
 _IP_TOS_INTERNETWORK   = 6;
 _IP_TOS_NETWORK        = 7;

 // ARP
 _ARP_REQUEST           = 1;
 _ARP_REPLY             = 2;

 // receive async messages (for packet listening) {$400 + 0}
 WM_ASYNCSELECT         = $0400 + 0;

 // server types
 SV_TYPE_WORKSTATION         = $00000001;
 SV_TYPE_SERVER              = $00000002;
 SV_TYPE_SQLSERVER           = $00000004;
 SV_TYPE_DOMAIN_CTRL         = $00000008;
 SV_TYPE_DOMAIN_BAKCTRL      = $00000010;
 SV_TYPE_TIME_SOURCE         = $00000020;
 SV_TYPE_AFP                 = $00000040;
 SV_TYPE_NOVELL              = $00000080;
 SV_TYPE_DOMAIN_MEMBER       = $00000100;
 SV_TYPE_PRINTQ_SERVER       = $00000200;
 SV_TYPE_DIALIN_SERVER       = $00000400;
 SV_TYPE_XENIX_SERVER        = $00000800;
 SV_TYPE_SERVER_UNIX         = SV_TYPE_XENIX_SERVER;
 SV_TYPE_NT                  = $00001000;
 SV_TYPE_WFW                 = $00002000;
 SV_TYPE_SERVER_MFPN         = $00004000;
 SV_TYPE_SERVER_NT           = $00008000;
 SV_TYPE_POTENTIAL_BROWSER   = $00010000;
 SV_TYPE_BACKUP_BROWSER      = $00020000;
 SV_TYPE_MASTER_BROWSER      = $00040000;
 SV_TYPE_DOMAIN_MASTER       = $00080000;
 SV_TYPE_SERVER_OSF          = $00100000;
 SV_TYPE_SERVER_VMS          = $00200000;
 SV_TYPE_WINDOWS             = $00400000;
 SV_TYPE_DFS                 = $00800000;
 SV_TYPE_ALTERNATE_XPORT     = $20000000;
 SV_TYPE_LOCAL_LIST_ONLY     = $40000000;
 SV_TYPE_DOMAIN_ENUM         = $80000000;
 SV_TYPE_ALL                 = $FFFFFFFF;

// ----------------------------------------------------------------------------
// Logicial Link Control Header
// ----------------------------------------------------------------------------
  DSAP_Netware = $E0;
  DSAP_SNAP = $AA;
  DSAP_SpanningTreeBPDU = $42;

// ----------------------------------------------------------------------------
// SubNetwork Access Control Header
// ----------------------------------------------------------------------------
  OrgIDCisco = $00000C;
  ProtoCPD = $2000;

// ----------------------------------------------------------------------------
// IPX Header
// ----------------------------------------------------------------------------
  PacketType_IPX = $00;
  PacketType_RIP = $01;
  PacketType_Echo = $02;
  PacketType_Error = $03;
  PacketType_PEP = $04;
  PacketType_SPX = $05;
  PacketType_NCP = $11;
  PacketType_NetBIOS_Broadcast = $14;

  Socket_Cisco_Ping = $0002;
  Socket_NCP = $0451;
  Socket_SAP = $0452;
  Socket_RIP = $0453;
  Socket_NetBIOS = $0455;
  Socket_Diag = $0456;
  Socket_Serialzation = $0457;
  Socket_NWLinkSMBServer = $0550;
  Socket_NWLinkSMBNameQuery = $0551;
  Socket_NWLinkSMBRedirector = $0552;
  Socket_NWLinkSMBMailSlotDatagram = $0553;
  Socket_NWLinkSMBMessenger = $0554;
  Socket_NWLinkSMBBrowse = $0555;
  Socket_AttachmateGW = $055D;
  Socket_IPXMsg1 = $4001;
  Socket_IPXMsg2 = $4003;
  Socket_NetwareDirectoryServer = $4006;
  Socket_HPLaserjet = $400c;
  Socket_Netware386 = $8104;
  Socket_ADSM = $8522;
  Socket_CiscoEIGRPforIPX = $85be;
  Socket_PowerChuteUPSMonitoring = $8f83;
  Socket_NewareLSP = $9001;
  Socket_IPXWAN = $9004;
  Socket_SNMPAgent = $900f;
  Socket_SNMPSink = $9010;
  Socket_SMSTesting = $907b;
  Socket_NovellPing = $9086;
  Socket_TCPTunnel = $9091;
  Socket_UDPTunnel = $9092;
  Socket_NDPSPrinterAgent = $90b2;
  Socket_NDPSBroker = $90b3;
  Socket_NDPSServiceRegistryService = $90b4;
  Socket_NDPSEventNotificationService = $90b5;
  Socket_NDPSNotifyListener = $90b7;
  Socket_NTServerRPCGW = $e885;

// ----------------------------------------------------------------------------
// RIP Header
// created by xnih 9 April 2005
// ----------------------------------------------------------------------------
  RipRequest = $0001;
  RipResponse = $0002;
  RipTraceOn = $0003;
  RipTraceOff = $0004;
  RipSun = $0005;

type
 QueryName        = array[0 .. 33] of char;
 MacAddress       = array[0..5] of Byte;
 IPAddress        = array[0..3] of Byte;

 // Packet buffer
 PacketBuffer     = Array[0..Max_Packet-1] of byte;
 CharPacketBuffer = Array[0..Max_Packet-1] of char;

 // Ethernet headers
 EthernetII_Header = record
   eth_dstmac    : MacAddress;
   eth_srcmac    : MacAddress;
   eth_proto     : Word;
 end;

 Ethernet8023_Header = record
   eth_dstmac    : array[0..5] of Byte;
   eth_srcmac    : array[0..5] of Byte;
   eth_len       : Word;
 end;

  // Virtual Lan 802.1q
  VLAN_Header = record
    Offset       : Word;
    Protocol     : Word;
  end;

 // good URL : http://www.networksorcery.com/enp/protocol/ip.htm
 // IP Header
 IP_Header = record
   ip_verlen       : Byte;     //verlen - 0x40 * 4 = header length?
   ip_tos          : Byte;
   ip_totallength  : Word;
   ip_id           : Word;
   ip_offset       : Word;
   ip_ttl          : Byte;
   ip_protocol     : Byte;
   ip_checksum     : Word;
   ip_srcaddr      : IPAddress;
   ip_dstaddr      : IPAddress;
 end;

// http://www.networksorcery.com/enp/protocol/ipv6.htm
// IP Header
 IPv6_Header = record
   ip_flowlabel    : longword;
   ip_payloadlength: word;
   ip_nextheader   : byte;
   ip_hoplimit     : byte;
   ip_srcaddr      : array [0..15] of byte;
   ip_dstaddr      : array [0..15] of byte;
 end;

//need to take into account IP Options, doh....  Which then means reading

 // good URL : http://www.networksorcery.com/enp/protocol/udp.htm
 // UDP Header
 UDP_Header = record
   src_portno    : Word;
   dst_portno    : Word;
   udp_length    : Word;
   udp_checksum  : Word;
 end;

 // good URL : http://www.networksorcery.com/enp/protocol/tcp.htm
 // TCP Header
 TCP_Header = record
   src_portno    : Word;
   dst_portno    : Word;
   tcp_seq       : LongWord;
   tcp_ack       : LongWord;
   offset        : Byte; // to be used with GenerateOffset
   flags         : Byte; // to be used with GenerateFlags
   tcp_window    : Word;
   tcp_checksum  : Word;
//   tcp_urgent    : Word;
 end;

 // good URL : http://www.networksorcery.com/enp/protocol/arp.htm
 // ARP Header
 ARP_Header  = record
   hw_type       : Word;
   proto_type    : Word;
   hw_addr_len   : Byte;
   proto_addr_len: Byte;
   opcode        : Word;
 end;

 ARP_Trailer = record
   junk          : array[0..199] of Byte;
 end;

{
 ARP_Header  = record
   hw_type       : Word;
   proto_type    : Word;
   hw_addr_len   : Byte;
   proto_addr_len: Byte;
   opcode        : Word;
   src_hw        : MacAddress;
   src_proto     : IPaddress;
   dst_hw        : MacAddress;
   dst_proto     : IPAddress;
   arp_trailer   : array[0..17] of Byte;
 end;
}

  LLC_Header = packed record
    DSAP:byte;                  //DSAP & IG Bit
    SSAP:byte;                  //SSAP & CR Bit
    ControlField:byte;
  end;

// ----------------------------------------------------------------------------
// SubNetwork Access Control Header
// ----------------------------------------------------------------------------
  SNAP_Header = packed record
    OrganizationID:array [0 .. 2] of byte;
    ProtocolType:word;
  end;

  IPX_Header = packed record
  	Checksum:word;
    Length:word;
    TransportControl:byte;
    PacketType:byte;
    DstNetwork:dword;
    DstNode:array [0 .. 5] of byte;
    DstSocket:word;
    SrcNetwork:dword;
    SrcNode:array [0 .. 5] of byte;
    SrcSocket:word
  end;

// ----------------------------------------------------------------------------
// RIP Header
// ----------------------------------------------------------------------------
  RIP_Header = packed record
    PacketType:word;
    RouteVector:array [0 .. 7] of byte;
  end;


var
  _packet                     : PacketBuffer;
  _ether                      : EthernetII_header;
  _vlan                       : VLAN_header;
  _ip                         : IP_header;
  _ipv6                       : IPv6_header;
  _ip_type                    : string;
  _udp                        : UDP_header;
  _tcp                        : TCP_header;
  _arp                        : ARP_header;
  _arp_restofit               : ARP_trailer;

  _ether8023                  : Ethernet8023_header;
  _llc                        : LLC_header;
  _snap                       : SNAP_header;
  _ipx                        : IPX_header;

  _is_a_vlan                  : boolean;
  _vlan_id                    : string;
  _is_EthernetII              : boolean;
  _is_Ethernet8023            : boolean;

  // proto details
  _ether_src                  : string;
  _ether_dst                  : string;
  _ether8023_src              : string;
  _ether8023_dst              : string;
  _ip_src                     : string;
  _ip_dst                     : string;
  _ip_hlen                    : integer;

  _arp_src_hw                 : string;
  _arp_src_proto              : string;
  _arp_dst_hw                 : string;
  _arp_dst_proto              : string;
  _arp_trailer                : string;

  _udp_data                   : string;
  _tcp_data                   : string;
  _tcp_flags                  : string;
  _tcp_hlen                   : integer;

// general purpose functions
function nearTTL(ttl : byte) : byte;
function UnMangle(qn : QueryName; var name : string) : boolean;
function GetOffset(data : Byte) : Byte;
function GetTCPFlags(data : Byte) : String;
function ServerTypeToString(st : dword) : string;
function HexToIP(s:array of byte):string;
function StrToIP(s:string):DWord;

// helper functions (to be improved - no size checks are performed)
function ConstructEtherII(size : integer) : boolean;
function ConstructVLAN(size : integer) : boolean;
function ConstructIP(size : integer) : boolean;
function ConstructARP(size : integer) : boolean;
function ConstructUDP(size : integer) : boolean;
function ConstructTCP(size : integer) : boolean;

//802.3 stuff (most of the time)
function ConstructEther8023(size : integer) : boolean;
function ConstructLLC(size : integer) : boolean;
function ConstructSNAP(size : integer) : boolean;
function ConstructIPX(size : integer) : boolean;

implementation

uses SysUtils;

function GetOffset(data : Byte) : Byte;
begin
  result := (data shr 4);
end;

function GetTCPFlags(data : Byte) : String;
var
  res : String;
begin
  res := '';

  {$IFDEF _TCP_ECN_SUPPORTED}
  // ECN (to be enabled)
  // right now, I don't know exactly what is it used for
  if (data and 128) > 0 then res := res + 'E';
  if (data and  64) > 0 then res := res + 'C';
  {$ENDIF}

  if (data and  1) > 0 then res := res + 'F';
  if (data and  2) > 0 then res := res + 'S';
  if (data and  4) > 0 then res := res + 'R';
  if (data and  8) > 0 then res := res + 'P';
  if (data and 16) > 0 then res := res + 'A';
  if (data and 32) > 0 then res := res + 'U';

  result := res;
end;

function nearTTL(ttl : byte) : byte;
begin
  // determine the closest TTL
  if (ttl>0) and (ttl<=16) then result:=16 else
  if (ttl>16) and (ttl<=32) then result:=32 else
  if (ttl>32) and (ttl<=60) then result:=60 else
  if (ttl>60) and (ttl<=64) then result:=64 else
  if (ttl>64) and (ttl<=128) then result:=128 else
  if (ttl>128) then result:=255 else result := ttl;
end;

function UnMangle(qn : QueryName; var name : string) : boolean;
var
  i, hi, lo : integer;
begin
  result := true;

  name   := '';

  for i:=0 to 14 do
    begin
      hi := ord(qn[i*2+1]) - ord('A');
      lo := ord(qn[i*2+2]) - ord('A');

      name := name + chr(hi * 16 + lo);
    end;
end;

function ServerTypeToString(st : dword) : string;
begin
  result := '';

  // if st and SV_TYPE_SERVER  > 0
  //    then result := result + 'Server, ';

  if st and SV_TYPE_DOMAIN_CTRL > 0 then result := result + 'Domain controller, ';
  if st and SV_TYPE_DOMAIN_BAKCTRL  > 0  then result := result + 'Backup domain controller, ';
  if st and SV_TYPE_SQLSERVER  > 0 then result := result + 'SQL server, ';
  if st and SV_TYPE_PRINTQ_SERVER  > 0 then result := result + 'Print queue, ';
  if st and SV_TYPE_DIALIN_SERVER  > 0 then result := result + 'Dialin server, ';
  if st and SV_TYPE_TIME_SOURCE  > 0 then result := result + 'Time server, ';
  if length(result) > 0 then delete(result, length(result)-1, 2);
end;

function ConstructEtherII(size : integer) : boolean;
var
  i,
  x : integer;
  s : string;

begin
  result := false;
  _is_EthernetII:=false;

  //zeroize things
  for x:=0 to length(_ether8023.eth_srcmac) - 1 do
    _ether.eth_dstmac[x]:=0;
  for x:=0 to length(_ether8023.eth_srcmac) - 1 do
    _ether.eth_srcmac[x]:=0;
  _ether.eth_proto:=0;
  _ether_src := '';
  _ether_dst := '';

  move(_packet, _ether, sizeof(EthernetII_Header));
  if ntohs(_ether.eth_proto) <= $05DC then exit;    //should we flush _ether then?

  for i:=0 to 5 do
    begin
      s := IntToHex(_ether.eth_srcmac[i], 2);
      if length(s) = 1 then s := '0' + s;
      _ether_src := _ether_src + s + ':';
     end;
  delete(_ether_src, length(_ether_src) , 1);

  for i:=0 to 5 do
    begin
      s := IntToHex(_ether.eth_dstmac[i], 2);
      if length(s) = 1 then s := '0' + s;
      _ether_dst := _ether_dst + s + ':';
    end;
  delete(_ether_dst, length(_ether_dst) , 1);

  _is_EthernetII:=true;
  result := true;
end;

function ConstructEther8023(size : integer) : boolean;
var
  i,
  x : integer;
  s : string;
begin
  result := false;
  _is_Ethernet8023:=false;

  //zeroize things
  for x:=0 to length(_ether8023.eth_dstmac) - 1 do
    _ether8023.eth_dstmac[x]:=0;
  for x:=0 to length(_ether8023.eth_srcmac) - 1 do
    _ether8023.eth_srcmac[x]:=0;
  _ether8023.eth_len:=0;
  _ether8023_src := '';
  _ether8023_dst := '';

  move(_packet, _ether8023, sizeof(Ethernet8023_Header));
  _ether8023.eth_len:=ntohs(_ether8023.eth_len);

  if _ether8023.eth_len > $05DC then
    begin
      for x:=0 to length(_ether8023.eth_dstmac) - 1 do
        _ether8023.eth_dstmac[x]:=0;
      for x:=0 to length(_ether8023.eth_srcmac) - 1 do
        _ether8023.eth_srcmac[x]:=0;
      _ether8023.eth_len:=0;
      exit;
    end;

  for i:=0 to 5 do
    begin
      s := IntToHex(_ether8023.eth_srcmac[i], 2);
      if length(s) = 1 then s := '0' + s;
      _ether8023_src := _ether8023_src + s + ':';
    end;
  delete(_ether8023_src, length(_ether8023_src) , 1);

  for i:=0 to 5 do
    begin
      s := IntToHex(_ether8023.eth_dstmac[i], 2);
      if length(s) = 1 then s := '0' + s;
      _ether8023_dst := _ether8023_dst + s + ':';
    end;
  delete(_ether8023_dst, length(_ether8023_dst) , 1);

  _is_Ethernet8023:=true;
  result := true;
end;

{
  Reason we have VLAN in here is that if we don't check for it our data will be
  off by a 'word' in size in cases where it exists since it is dropped in
  between EthernetII Header and IP Header

  If we do proper testing this may not be an issue, but if we don't check
  for VLAN we will miss any VLAN packets which are type $8100 and then have
  their own protocol section.

  May not matter though since it appears using the winpcap parser may filter
  vlan packets out at this point in time.
}
function ConstructVLAN(size : integer) : boolean;
var
  offset:integer;
  buffer:word;
  i:integer;

begin
  result := false;
  _is_a_vlan:=false;
  _vlan_id:='';

  if _ether.eth_proto <> $81 then exit;

  offset:=sizeof(EthernetII_Header);
  move(_packet[offset], _vlan, sizeof(VLAN_Header));

  //vlan protocols I don't want to use or have around right now:
  if ntohs(_vlan.Protocol) = $9000 then exit;

  result := true;
  _vlan_id:=IntToHex(ntohs(_vlan.Offset), 4);
  _vlan_id:='$' + copy(_vlan_id, 2, 3);
  _vlan_id:=IntToStr(StrToInt(_vlan_id));
  _is_a_vlan:=true;
end;

function HexToIP(s:array of byte):string;
var
  i:integer;
  ip:string;

begin
  ip:='';
  for i:=0 to 3 do
    begin
      ip := ip + IntToStr(s[i]) + '.';
    end;
  delete(ip, length(ip) , 1);
  result:=ip;
end;

function StrToIP(s: String): DWORD;
var
	i: Integer;
	Index: Integer;
	Digit: String;
	IP: array [0 .. 3] of DWORD;
	Len: Integer;
begin
	Index := 1;
	for i := 0 to 3 do
		IP[i] := 0;
	Len := Length(s);
	for i := 0 to 3 do
	begin
		Digit := '';
		while(s[Index] >= '0') and (s[Index] <= '9') and (Index <= Len) do
		begin
			Digit := Digit + s[Index];
			inc(Index);
		end;
		inc(Index);
		IP[i] := StrToInt(Digit);
	end;
	Result := IP[0] shl 24 + IP[1] shl 16 + IP[2] shl 8 + IP[3] shl 0;
end;

function ConstructIP(size : integer) : boolean;
var
  i,
  x,
  offset : integer;

begin
  result := false;
  if not ConstructEtherII(size) then exit;
  if (_ether.eth_proto <> $08) and (_ether.eth_proto <> $81) and (_ether.eth_proto <> $dd86) then exit;

  //zeroize things
  _ip.ip_verlen:=0;
  _ip.ip_tos:=0;
  _ip.ip_totallength:=0;
  _ip.ip_id:=0;
  _ip.ip_offset:=0;
  _ip.ip_ttl:=0;
  _ip.ip_protocol:=0;
  _ip.ip_checksum:=0;
  for x:=0 to length(_ip.ip_srcaddr) - 1 do
    _ip.ip_srcaddr[x]:=0;
  for x:=0 to length(_ip.ip_dstaddr) - 1 do
    _ip.ip_dstaddr[x]:=0;
  _ip_src := '';
  _ip_dst := '';

  ConstructVLAN(size);
  if _is_a_vlan then
    begin
      if (_vlan.Protocol <> $08) and (_vlan.Protocol <> $dd86) then exit;

      //made sure that we are in a IP VLAN
      offset:=sizeof(EthernetII_Header)+sizeof(VLAN_Header);
      if _vlan.Protocol = $08 then
        begin
          _ip_type:='v4';
          move(_packet[offset], _ip, sizeof(IP_Header));
        end;
      if _vlan.Protocol = $dd86 then
        begin
          _ip_type:='v6';
          move(_packet[offset], _ipv6, sizeof(IPv6_Header));
        end;
    end
  else
    _vlan_id:='';

  if _ether.eth_proto = $08 then
    begin
      _ip_type:='v4';
      move(_packet[sizeof(EthernetII_Header)], _ip, sizeof(IP_Header));
    end;

  if _ether.eth_proto = $dd86 then
    begin
      _ip_type:='v6';
      move(_packet[sizeof(EthernetII_Header)], _ipv6, sizeof(IPv6_Header));
    end;

  if _ip_type = 'v4' then
    begin
      _ip_src:=HexToIP(_ip.ip_srcaddr);
      _ip_dst:=HexToIP(_ip.ip_dstaddr);

      _ip_hlen:=(_ip.ip_verlen - 64) * 4;
    end;

  if _ip_type ='v6' then
    begin
      for x:=0 to 15 do
        begin
          if x mod 2 = 0 then
            _ip_src:=_ip_src + ':';
          if IntToHex(_ipv6.ip_srcaddr[x], 2) <> '00' then
            _ip_src:=_ip_src+IntToHex(_ipv6.ip_srcaddr[x], 2);
        end;
      delete(_ip_src, 1, 1);
      x:=pos(':::', _ip_src);
      while x > 0 do
        begin
          delete(_ip_src, x, 1);
          x:=pos(':::', _ip_src);
        end;
      x:=pos(':0', _ip_src);
      while x > 0 do
        begin
          delete(_ip_src, x+1, 1);
          x:=pos(':0', _ip_src);
        end;
      x:=length(_ip_src);
      if _ip_src[x] = ':' then
        _ip_src:=_ip_src + '0';

      for x:=0 to 15 do
        begin
          if x mod 2 = 0 then
            _ip_dst:=_ip_dst + ':';
          if IntToHex(_ipv6.ip_dstaddr[x], 2) <> '00' then
            _ip_dst:=_ip_dst+IntToHex(_ipv6.ip_dstaddr[x], 2);
        end;
      delete(_ip_dst, 1, 1);
      x:=pos(':::', _ip_dst);
      while x > 0 do
        begin
          delete(_ip_dst, x, 1);
          x:=pos(':::', _ip_dst);
        end;
      x:=pos(':0', _ip_dst);
      while x > 0 do
        begin
          delete(_ip_dst, x+1, 1);
          x:=pos(':0', _ip_dst);
        end;
      x:=length(_ip_dst);
      if _ip_dst[x] = ':' then
        _ip_dst:=_ip_dst + '0';

      _ip_hlen:=sizeof(IPv6_Header);
    end;

  if _ip_hlen > 20 then
    i:=i;  //need to compute IP Options which are rare, but do seem to happen!

  result := true;
end;

{function ConstructARP(size : integer) : boolean;
var
  i,
  offset : integer;
  s : string;

begin
  result := false;
  ConstructEtherII(size);

  if _ether.eth_proto = $81 then   //vlan'd traffic
    begin
      ConstructVLAN(size);
      if ntohs(_vlan.Protocol) <> $0806 then exit;
      offset:=sizeof(EthernetII_Header) + sizeof(VLAN_Header)
    end
  else
    begin
      if ntohs(_ether.eth_proto) <> $0806 then exit;
      offset:=sizeof(EthernetII_Header);
    end;

  move(_packet[offset], _arp, sizeof(ARP_Header));

  result := true;

  _arp.hw_type     := ntohs(_arp.hw_type);
  _arp.proto_type  := ntohs(_arp.proto_type);
  _arp.opcode      := ntohs(_arp.opcode);

  _arp_src_hw := '';
  for i:=0 to _arp.hw_addr_len - 1 do
    begin
      s := IntToHex(_arp.src_hw[i], 2);
      if length(s) = 1 then s := '0' + s;
      _arp_src_hw := _arp_src_hw + s + ':';
    end;
  delete(_arp_src_hw, length(_arp_src_hw) , 1);

  _arp_dst_hw := '';
  for i:=0 to _arp.hw_addr_len - 1 do
    begin
      s := IntToHex(_arp.dst_hw[i], 2);
      if length(s) = 1 then s := '0' + s;
      _arp_dst_hw := _arp_dst_hw + s + ':';
    end;
  delete(_arp_dst_hw, length(_arp_dst_hw), 1);

  _arp_src_proto := '';
  for i:=0 to _arp.proto_addr_len - 1 do
    begin
      _arp_src_proto := _arp_src_proto + IntToStr(_arp.src_proto[i]) + '.';
    end;
  delete(_arp_src_proto, length(_arp_src_proto), 1);

  _arp_dst_proto := '';
  for i:=0 to _arp.proto_addr_len - 1 do
    begin
      _arp_dst_proto := _arp_dst_proto + IntToStr(_arp.dst_proto[i]) + '.';
    end;
  delete(_arp_dst_proto, length(_arp_dst_proto), 1);

  _arp_trailer := '';
  for i:=0 to 17 do
    begin
      _arp_trailer := _arp_trailer + IntToHex(_arp.arp_trailer[i],2);
    end;

end; }

function ConstructARP(size : integer) : boolean;
var
  i,
  offset, bump : integer;
  s : string;

begin
  result := false;
  ConstructEtherII(size);

  if _ether.eth_proto = $81 then   //vlan'd traffic
    begin
      ConstructVLAN(size);
      if ntohs(_vlan.Protocol) <> $0806 then exit;
      offset:=sizeof(EthernetII_Header) + sizeof(VLAN_Header)
    end
  else
    begin
      _vlan_id:='';
      if ntohs(_ether.eth_proto) <> $0806 then exit;
      offset:=sizeof(EthernetII_Header);
    end;

  move(_packet[offset], _arp, sizeof(ARP_Header));
  offset:=offset + sizeof(ARP_Header);
  move(_packet[offset], _arp_restofit, sizeof(ARP_Trailer));

  result := true;

  _arp.hw_type     := ntohs(_arp.hw_type);
  _arp.proto_type  := ntohs(_arp.proto_type);
  _arp.opcode      := ntohs(_arp.opcode);

  bump:=0;
  _arp_src_hw := '';
  for i:=0 to _arp.hw_addr_len - 1 do
    begin
      s := IntToHex(_arp_restofit.junk[bump + i], 2);
      if length(s) = 1 then s := '0' + s;
      _arp_src_hw := _arp_src_hw + s + ':';
    end;
  delete(_arp_src_hw, length(_arp_src_hw) , 1);
  bump:=bump + _arp.hw_addr_len;

  _arp_src_proto := '';
  for i:=0 to _arp.proto_addr_len - 1 do
    begin
      _arp_src_proto := _arp_src_proto + IntToStr(_arp_restofit.junk[bump + i]) + '.';
    end;
  delete(_arp_src_proto, length(_arp_src_proto), 1);
  bump:=bump + _arp.proto_addr_len;

  _arp_dst_hw := '';
  for i:=0 to _arp.hw_addr_len - 1 do
    begin
      s := IntToHex(_arp_restofit.junk[bump + i], 2);
      if length(s) = 1 then s := '0' + s;
      _arp_dst_hw := _arp_dst_hw + s + ':';
    end;
  delete(_arp_dst_hw, length(_arp_dst_hw), 1);
  bump:=bump + _arp.hw_addr_len;

  _arp_dst_proto := '';
  for i:=0 to _arp.proto_addr_len - 1 do
    begin
      _arp_dst_proto := _arp_dst_proto + IntToStr(_arp_restofit.junk[bump + i]) + '.';
    end;
  delete(_arp_dst_proto, length(_arp_dst_proto), 1);
  bump:=bump + _arp.proto_addr_len;

  _arp_trailer := '';
  for i:=0 to size - bump - offset - 1 do
    begin
      _arp_trailer := _arp_trailer + IntToHex(_arp_restofit.junk[bump + i],2);
    end;
end;

function ConstructUDP(size : integer) : boolean;
var
  offset:integer;

begin
  result := false;

  if not ConstructIP(size) then exit;
  if _ip_type = 'v4' then
    if _ip.ip_protocol <> _IPPROTO_UDP then exit;
  if _ip_type = 'v6' then
    if _ipv6.ip_nextheader <> _IPPROTO_UDP then exit;

  //zeroize things
  _udp.src_portno:=0;
  _udp.dst_portno:=0;
  _udp.udp_length:=0;
  _udp.udp_checksum:=0;

  if _is_a_vlan then
    offset:=sizeof(EthernetII_Header) + sizeof(VLAN_Header) + _ip_hlen
  else
    offset:=sizeof(EthernetII_Header) + _ip_hlen;
  move(_packet[offset], _udp, sizeof(UDP_Header));

  _udp.src_portno := ntohs(_udp.src_portno);
  _udp.dst_portno := ntohs(_udp.dst_portno);
  _udp.udp_length := ntohs(_udp.udp_length);

  result := true;
end;

function ConstructTCP(size : integer) : boolean;
var
  offset,
  len : integer;

begin
  result := false;

  if not ConstructIP(size) then exit;

  if _ip_type = 'v4' then
    if _ip.ip_protocol <> _IPPROTO_TCP then exit;

  if _ip_type = 'v6' then
    if _ipv6.ip_nextheader <> _IPPROTO_TCP then exit;

  if _is_a_vlan then
    offset:=sizeof(EthernetII_Header) + sizeof(VLAN_Header) + _ip_hlen
  else
    offset:=sizeof(EthernetII_Header) + _ip_hlen;
  move(_packet[offset], _tcp, sizeof(TCP_Header));

  _tcp.src_portno := ntohs(_tcp.src_portno);
  _tcp.dst_portno := ntohs(_tcp.dst_portno);

  _tcp_flags := GetTCPFlags(_tcp.flags);

  _tcp_data  := '';
  _tcp_hlen:=GetOffset(_tcp.offset) * 4;

  if _is_a_vlan then
    offset := sizeof(EthernetII_Header) + sizeof(VLAN_Header) + _ip_hlen + _tcp_hlen
  else
    offset := sizeof(EthernetII_Header) + _ip_hlen + _tcp_hlen;
  for len  := offset to size - 1 do
    _tcp_data := _tcp_data + chr(_packet[len]);

  result := true;
end;

function ConstructLLC(size : integer) : boolean;
var
  offset:integer;

begin
  result := false;

  if ConstructEther8023(size) then
    begin
      _vlan_id:='';  //not sure it is needed, but just in case
      offset:=sizeof(Ethernet8023_Header);
      move(_packet[offset], _llc, sizeof(LLC_Header));
    end
  else if ConstructEtherII(size) then
    begin
      ConstructVLAN(size);

      if _is_a_vlan then
        offset:=sizeof(EthernetII_Header) + sizeof(VLAN_Header)
      else
        offset:=sizeof(EthernetII_Header);
      move(_packet[offset], _llc, sizeof(LLC_Header));
    end
  else
    exit;

  result := true;
end;

function ConstructSNAP(size : integer) : boolean;
var
  offset:integer;

begin
  result := false;

  if not ConstructLLC(size) then exit;
  if _llc.DSAP <> $aa then exit;

  if _is_a_vlan then
    offset:=sizeof(EthernetII_Header) + sizeof(VLAN_Header) + sizeof(LLC_Header)
  else
    offset:=sizeof(Ethernet8023_Header) + sizeof(LLC_Header);
  move(_packet[offset], _snap, sizeof(SNAP_Header));

  _snap.ProtocolType:=ntohs(_snap.ProtocolType);

  result := true;
end;

function ConstructIPX(size : integer) : boolean;
var
  offset:integer;

begin
  result := false;

  offset:=0;

  ConstructEther8023(size);
  if _is_Ethernet8023 then
    begin
      if not ConstructLLC(size) then exit;
      if _llc.DSAP <> $e0 then exit;
      offset:=sizeof(Ethernet8023_Header) + sizeof(LLC_Header);
    end
  else
    begin
      ConstructEtherII(size);
      if _is_EthernetII then
       if ntohs(_ether.eth_proto) <> $8137 then exit;
      offset:=sizeof(EthernetII_Header);
    end;

  if offset <> 0 then
    begin
      move(_packet[offset], _ipx, sizeof(IPX_Header));
      _ipx.SrcSocket := ntohs(_ipx.SrcSocket);
      _ipx.DstSocket := ntohs(_ipx.DstSocket);

      result := true;
    end;
end;

end.

