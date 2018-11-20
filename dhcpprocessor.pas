{-----------------------------------------------------------------------------
 Unit Name: Bootp
 Author:    xnih
 Date:      13-June-2005
 Modified:  5-July-2006
 Purpose:   Bootp/DHCP related stuff
 History:
-----------------------------------------------------------------------------}
unit DHCPProcessor;

interface

uses
  protocolheaders, sysutils, pcap, sockets, fingerprint_dhcp, generaltypes;

type

// ----------------------------------------------------------------------------
// BootStrap Protocol
// ----------------------------------------------------------------------------
  BootStrap_Header = packed record
    MessageType : byte;
    HardwareType : byte;
    HardwareAddLen : byte;
    Hops : byte;
    Transaction: Dword;
    ElapsedTime: word;
    bootpflags: word;
    ClientIPAdd: array[0..3] of Byte;
    YourIPAdd: array[0..3] of Byte;
    NextServerIPAdd: array[0..3] of Byte;
    RelayAgentIPAdd: array[0..3] of Byte;
    ClientHWAdd: array[0..5] of Byte;
    Unknown: array [0..9] of byte;
    ServerHostName: array [0..63] of byte;
    BootFile: array [0..127] of byte;
    MagicCookie: dword;
  end;

  Bootp_Options = packed record
    options : PacketBuffer;
  end;

  BootpOptionsRec = packed record
    options:string;
    LeaseTime:string;
    Request:string;
    ParamRequestList:string;
    MaxSize:string;
    ClientID:string;
    IPAddRequest:string;
    Router:string;
    Subnet:string;
    HostName:string;
    FQDN:string;
    VendorClass:string;
    VendorSpecific:string;
    UserClass:string;
    unKnown:string;
  end;

var
  _bootp                      : BootStrap_Header;
  _bootp_options              : Bootp_Options;
  _bootp_options_rec          : BootpOptionsRec;

function ConstructBootStrap(size : integer) : boolean;
function ConstructBootpOptions(size : integer) : boolean;
function ConstructDecodeBootpOptions(var buff; size:integer) : boolean;
function Parse_DHCP(const Header: PPPcap_Pkthdr; const Data: Pointer; info : pDLLInfo; debug:boolean):widestring;

implementation

function Parse_DHCP(const Header: PPPcap_Pkthdr; const Data: Pointer; info : pDLLInfo; debug:boolean):widestring;
var
  mac, ip, bootptype, options, option55, vendorclass, flags, secs, TransID: string;
  x:integer;
  t:tdatetime;
  ignoreType, UseAny:boolean;
  s, s1, s2, os:widestring;

begin
  result:='';
  
  if Header^^.Len >= Max_Packet then exit;

  move(data^, _packet, Header^^.Len);

  if not ConstructDecodeBootpOptions(_Bootp_options.Options, Header^^.Len) then exit;

  if (_bootp_options_rec.Request < #1) and (_bootp_options_rec.Request > #8) then exit;

  ip:=_ip_src;

  if _bootp.MessageType = 1 then   //Request from Client (Discover/Request/Inform)
    begin
      //this gives us the mac according to the DHCP request, should be more reliable since router may have changed it in the ethernet II heading!
      mac:='';

      for x:=0 to 5 do
        mac:=mac + IntToHex(_bootp.ClientHWAdd[x],2) + ':';
      mac:=copy(mac, 1, length(mac) - 1);

      if mac <> _ether_src then
        ip:=HexToIP(_bootp.ClientIPAdd);

      if mac = '00:00:00:00:00:00' then //mac address not given
        mac:=_ether_src;
    end
  else if _bootp.MessageType = 2 then   //DHCP Reply from a DHCP Server   (Offer/ACK)
    mac:=_ether_src
  else
    mac:='unknown';

  bootptype:=_bootp_options_rec.request;
  if _bootp_options_rec.request = #1 then bootptype:='Discover';
  if _bootp_options_rec.request = #2 then bootptype:='Offer';
  if _bootp_options_rec.request = #3 then bootptype:='Request';
  if _bootp_options_rec.request = #4 then bootptype:='Decline';
  if _bootp_options_rec.request = #5 then bootptype:='ACK';
  if _bootp_options_rec.request = #6 then bootptype:='NAK';
  if _bootp_options_rec.request = #7 then bootptype:='Release';
  if _bootp_options_rec.request = #8 then bootptype:='Inform';
  if _bootp_options_rec.request = #9 then bootptype:='Force Renew';
  if _bootp_options_rec.request = #10 then bootptype:='Lease Query';
  if _bootp_options_rec.request = #11 then bootptype:='Lease Unassigned';
  if _bootp_options_rec.request = #12 then bootptype:='Lease Unknown';
  if _bootp_options_rec.request = #13 then bootptype:='Lease Active';

  options:=_bootp_options_rec.options;
  option55:=_bootp_options_rec.ParamRequestList;
  vendorclass:=_bootp_options_rec.VendorClass;
  TransID:='0x' + IntToHex(ntohl(_bootp.Transaction), 4);
  Flags:=IntToHex(ntohs(_bootp.bootpflags), 2);
  if Flags = '8000' then Flags:='Broadcast';
  if Flags = '00' then Flags:='Unicast';
  secs :=IntToStr(ntohs(_bootp.ElapsedTime));

  IgnoreType:=info^.DHCPIgnoreType;
  UseAny:=info^.UseAny;

  os := FindDHCPOS(options, option55, vendorclass, bootptype, ignoretype, useAny);

  s:=ip + ';' + mac + ';DHCP;' + os;

  if debug then
    s:=s + chr(10) + chr(9) + bootptype + ';' + options + ';' + option55 + ';' + vendorclass;

  result:=s;
end;


function ConstructBootStrap(size : integer) : boolean;
var
  offset,
  x : integer;

begin
  result := false;

  if not ConstructUDP(size) then exit;
  if (_udp.dst_portno <> 67) and (_udp.dst_portno <> 68) then exit;

  //zeroize things
  _bootp.MessageType:=0;
  _bootp.HardwareType:=0;
  _bootp.HardwareAddLen:=0;
  _bootp.Hops:=0;
  _bootp.Transaction:=0;
  _bootp.ElapsedTime:=0;
  _bootp.bootpflags:=0;
  for x := 0 to 3 do
    begin
      _bootp.ClientIPAdd[x]:=0;
      _bootp.YourIPAdd[x]:=0;
      _bootp.NextServerIPAdd[x]:=0;
      _bootp.RelayAgentIPAdd[x]:=0;
    end;
  for x:=0 to length(_bootp.ClientHWAdd) - 1 do
    _bootp.ClientHWAdd[x]:=0;
  for x:=0 to length(_bootp.Unknown) - 1 do
    _bootp.Unknown[x]:=0;
  for x:=0 to length(_bootp.ServerHostName) - 1 do
    _bootp.ServerHostName[x]:=0;
  for x:=0 to length(_bootp.BootFile) - 1 do
    _bootp.BootFile[x]:=0;
  _bootp.MagicCookie:=0;

  if _is_a_vlan then
    offset:=sizeof(EthernetII_Header) + sizeof(VLAN_Header) + _ip_hlen + sizeof(UDP_Header)
  else
    offset:=sizeof(EthernetII_Header) + _ip_hlen + sizeof(UDP_Header);
 move(_packet[offset], _bootp, sizeof(BootStrap_Header));

  //1 = Request
  //2 = Reply
 if (_bootp.MessageType = 1) or  (_bootp.MessageType = 2) then result:=true;
end;

function ConstructBootpOptions(size : integer) : boolean;
var
  len, maxlen,
  offset,
  x: integer;

begin
  result := false;

  if not ConstructBootStrap(size) then exit;

  //zeroize things
  for x:=0 to length(_bootp_options.options) - 1 do
    _bootp_options.options[x]:=0;

  len:=_udp.udp_length - sizeof(UDP_Header) - sizeof(BootStrap_Header);

  if _is_a_vlan then
    offset:=sizeof(EthernetII_Header) + sizeof(VLAN_Header) + _ip_hlen + sizeof(UDP_Header) + sizeof(BootStrap_Header)
  else
    offset:=sizeof(EthernetII_Header) + _ip_hlen + sizeof(UDP_Header) + sizeof(BootStrap_Header);

  maxlen:=size - offset;  //max length bootstrap stuff could be.
  if len > maxlen then
    len:=maxlen;

  move(_packet[offset], _bootp_options, len);
  if len > 0 then result:=true;
end;


function ConstructDecodeBootpOptions(var buff; size:integer) : boolean;
type
    temparray = array [0..256] of byte;
//    TByteArray = Array[0..0] of Byte;
var
  i : integer;
  done        : boolean;
  res         : String;
  len, x      : integer;
  t:temparray;
  s:string;

begin
  result := false;

  if not ConstructBootpOptions(size) then exit;
  
  //zeroize things
  for i:=0 to 256 do
    t[i]:=0;

  _bootp_options_rec.unKnown:='';
  _bootp_options_rec.FQDN:='';
  _bootp_options_rec.ClientID:='';
  _bootp_options_rec.VendorClass:='';
  _bootp_options_rec.VendorSpecific:='';
  _bootp_options_rec.UserClass:='';
  _bootp_options_rec.MaxSize:='';;
  _bootp_options_rec.ParamRequestList:='';
  _bootp_options_rec.Request:='';
  _bootp_options_rec.LeaseTime:='';
  _bootp_options_rec.IPAddRequest:='';
  _bootp_options_rec.Router:='';
  _bootp_options_rec.Subnet:='';
  _bootp_options_rec.HostName:='';

  res:='';

  size:=_udp.udp_length - sizeof(UDP_Header) - sizeof(BootStrap_Header);
  if size > 0 then
  begin
    i:=0;
    done:=false;

    while not done do
      begin
        s:='';
        // check for a known option
        case TByteArray(buff)[i] of
          00: {padding}
            begin
              inc(i);
            end;
          1: {1 - Subnet}
            begin
              res := res + '1,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=0 to len-1 do
                  s:=s+IntToStr(t[x])+'.';
                delete(s, length(s), 1);
                _bootp_options_rec.Subnet:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          3: {3 - Router Address}
            begin
              res := res + '3,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=0 to len-1 do
                  s:=s+IntToStr(t[x])+'.';
                delete(s, length(s), 1);
                _bootp_options_rec.Router:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          12: {12 - host name}
            begin
              res := res + '12,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=0 to len-1 do        //works good
                  if t[x] <> 0 then
                    s:=s+chr(t[x]);
                _bootp_options_rec.HostName:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          43: {43 - Vendor Specific}
            begin
              res := res + '43,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=0 to len-1 do        //works good
                  s:=s+chr(t[x]);
                _bootp_options_rec.VendorSpecific:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          50: {50 - IP Address Request}
            begin
              res := res + '50,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=0 to len-1 do
                  s:=s+IntToStr(t[x])+'.';
                delete(s, length(s), 1);
                _bootp_options_rec.IPAddRequest:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          51: {51 - Lease Time}
            begin
              res := res + '51,';
              try
                len:=TByteArray(buff)[i+1];
                Move(TByteArray(buff)[i+2], t, len);
                for x:=0 to len-1 do
                  s:=s+ IntToHex(t[x],2);
                s:=IntToStr(StrToInt('$' + s));
                if s <> '-1' then
                  _bootp_options_rec.LeaseTime:=s
                else
                  _bootp_options_rec.LeaseTime:='infinite';
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          53: {53 - DHCP Request}

             { 1     DHCPDISCOVER
               2     DHCPOFFER
               3     DHCPREQUEST
               4     DHCPDECLINE
               5     DHCPACK
               6     DHCPNAK
               7     DHCPRELEASE
               8     INFORM
               9     Force Renew
              10     Lease Query
              11     Lease Unassigned
              12     Lease Unknown
              13     Lease Active}

            begin  //need to even do this one?
              res := res + '53,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=0 to len-1 do
                  s:=s+chr(t[x]);
                _bootp_options_rec.Request:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          55: {55 - Param Request}
            begin
              res := res + '55,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=0 to len-1 do      //need to put comma's in it and need to convert to num not char
                  s:=s + IntToStr(t[x]) + ',';
                s:=copy(s, 1, length(s) - 1);
                _bootp_options_rec.ParamRequestList:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          57: {57 - Max Size}
            begin
              res := res + '57,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=0 to len-1 do
                  s:=s+ IntToHex(t[x],2);
                s:=IntToStr(StrToInt('$' + s));
                _bootp_options_rec.MaxSize:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          60: {60 - Vendor Class Identifier}
            begin
              res := res + '60,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=0 to len-1 do //works
                  if (t[x] >= 32) and (t[x] <=126) then
                    s:=s+chr(t[x]);
                _bootp_options_rec.VendorClass:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          61: {61 - Client Identifier (MAC)}
            begin
              res := res + '61,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=1 to len-1 do   //works
                  begin
                    if t[0]=1 then //ethernet
                      s:=s + IntToHex(t[x], 2) + ':'
                    else
                      if (t[x] >= 32) and (t[x] <=126) then       //may need tweaked
                        s:=s+chr(t[x]);
                  end;
                if s[length(s)] = ':' then
                  _bootp_options_rec.ClientID:=copy(s, 1, length(s) - 1)
                else
                  _bootp_options_rec.ClientID:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          77: {77 - User Class Identifier}
            begin
              res := res + '77,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=0 to len-1 do //works
                  if (t[x] >= 32) and (t[x] <=126) then
                    s:=s+chr(t[x]);
                _bootp_options_rec.UserClass:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          81: {81 - Client FQDN}
            begin
              res := res + '81,';
              len:=TByteArray(buff)[i+1];
              try
                Move(TByteArray(buff)[i+2], t, len);
                for x:=3 to len-1 do      //for some reason 3 nil chars start it off, but that is in the packet, so skipping them
                  s:=s+chr(t[x]);
                _bootp_options_rec.FQDN:=s;
              except
                ;
              end;
              i:=i + 2 + len;
            end;
          255: done:=true;
        else
          begin
            res := res + IntToStr(TByteArray(buff)[i]) + ',';
            len:=TByteArray(buff)[i+1];
            try
              Move(TByteArray(buff)[i+2], t, len);
              for x:=0 to len-1 do
                s:=s+chr(t[x]);
              _bootp_options_rec.unKnown:=_bootp_options_rec.unKnown + IntToStr(TByteArray(buff)[i]) + s + ',';
            except
              ;
            end;
            i:=i + 2 + len;
          end;
        end;

        // check if we are done ...
        if i >= size then done := true;
      end;
  end;

  _bootp_options_rec.options:=copy(res, 1, length(res) - 1);  //get rid of last ,
  if res <> '' then result:=true;
end;

end.

