unit TCPConnectionProcessor;

interface

uses
  protocolheaders,sockets, sysutils, pcap, generaltypes, fingerprint_tcp;

var
  _tcp_connection             : string;

  _tcp_options                : string;

  _options_mss                : integer;
  _options_ts                 : integer;
  _options_er                 : integer;
  _options_win                : integer;
  _options_echo_reply         : integer;

function DecodeTCPOptions(var buff; size : Word; with_details : boolean) : String;
function ConstructTCPOptions(size:integer):boolean;
function Parse_TCP(const Header: PPPcap_Pkthdr; const Data: Pointer; info : pDLLInfo; debug:boolean):widestring;

implementation

function Parse_TCP(const Header: PPPcap_Pkthdr; const Data: Pointer; info : pDLLInfo; debug:boolean):widestring;
var
  ip,mac,_tcp_signature, _ettercap_signature, _p0f_signature:string;
  window, ttl, mss, ws, mtu:integer;
  offset:byte;
  df,p,q:integer;
  found:boolean;
  s,os,tcpfp, ettercapfp, p0ffp:widestring;

begin
  result:='';
  
  if Header^^.Len >= Max_Packet then exit;

  move(data^, _packet, Header^^.Len);

  if not ConstructTCPOptions(Header^^.Len) then exit;

  if (_tcp_flags <> 'S') and (_tcp_flags <> 'SA') then exit;

  //Too common
{//  if (_tcp_flags = 'A') and (_tcp_options = 'N,N,K:.') then exit;
//  if (_tcp_flags = 'A') and (_tcp_options = 'N,N,T:.') then exit;
  if (_tcp_flags = 'A') then exit;
  if (_tcp_flags = 'FA') and (_tcp_options = 'N,N,T:F') then exit;
  if (_tcp_flags = 'PA') and (_tcp_options = 'N,N,T:DF') then exit;
}

  _tcp_signature:='';
  _ettercap_signature:='';
  _p0f_signature:='';
  mtu:=0;

  window:=ntohs(_tcp.tcp_window);

  if _ip_type = 'v4' then
    ttl:=nearTTL(_ip.ip_ttl);
  if _ip_type = 'v6' then
    ttl:=nearTTL(_ipv6.ip_hoplimit);

  s:=_tcp_options;
  p:=pos('M', s);
  if p > 0 then
    begin
      s:=copy(s, p+1, length(s)-p);  //drop the M and anything before it
      p:=pos(',', s);
      if p = 0 then
        p:=pos(':', s);
      s:=copy(s, 1, p-1);
      mss:=StrToInt(s);
      s:=IntToHex(mss, 4);
    end
  else //no MSS
    begin
      s:='_MSS';
      mss:=0;
    end;

  _tcp_signature:=_tcp_signature + IntToStr(window) + ':';
  _tcp_signature:=_tcp_signature + IntToStr(ttl) + ':';

  if (window <> 0) and (mss <> 0) then
    begin
      found:=false;
      q:=window mod mss;
      if q = 0 then
        begin
          q:=window div mss;
          _p0f_signature:=_p0f_signature + 'S' + IntToStr(q) + ':';
          found:=true;
        end;

      mtu:=mss + 40; //probably should be _ip_hlen + _tcp_hlen, but then have to remove length of tcp options also
      q:=window mod mtu;
      if q = 0 then
        begin
          q:=window div mtu;
          _p0f_signature:=_p0f_signature + 'T' + IntToStr(q) + ':';
          found:=true;
        end;

      if found = false then
        _p0f_signature:=_p0f_signature + IntToStr(window) + ':';
    end
  else
    _p0f_signature:=_p0f_signature + IntToStr(window) + ':';

  _p0f_signature:=_p0f_signature + IntToStr(ttl) + ':';

  if ttl = 60 then
    ttl:=64; //ettercap use a ttl of 64, not 60...  may have to do this in p0f also....

  _ettercap_signature:=_ettercap_signature + IntToHex(window,4) + ':';
  _ettercap_signature:=_ettercap_signature + s + ':';  //where s = mss converted

  s:=IntToHex(TTL,2);
  _ettercap_signature:=_ettercap_signature + s + ':';

  s:=_tcp_options;
  p:=pos('W', s);
  if p > 0 then
    begin
      s:=copy(s, p+1, length(s)-p);  //drop the W and anything before it
      p:=pos(',', s);
      if p = 0 then
        p:=pos(':', s);
      s:=copy(s, 1, p-1);
      ws:=StrToInt(s);
      s:=IntToHex(ws, 2);
    end
  else //no WS
    s:='WS';

  _ettercap_signature:=_ettercap_signature + s + ':';

  s:=_tcp_options;
  p:=pos('S', s);
  if p > 0 then
    _ettercap_signature:=_ettercap_signature + '1:'
  else
    _ettercap_signature:=_ettercap_signature + '0:';

  s:=_tcp_options;
  p:=pos('N', s);
  if p > 0 then
    _ettercap_signature:=_ettercap_signature + '1:'
  else
    _ettercap_signature:=_ettercap_signature + '0:';

  //determine don't fragment
  //no idea if this is in ipv6!  don't think it is

  if _ip_type = 'v4' then
    begin
      move(_ip.ip_offset, offset, 1);
      offset:=getoffset(offset);
    end
  else
    offset:=0;  //not sure how much this will hose this up, but wworks for now to avert a crash

  if (offset and 4) > 0 then
    begin
      df:=1;
      _ettercap_signature:=_ettercap_signature + '1:';
    end
  else
    begin
      df:=0;
      _ettercap_signature:=_ettercap_signature + '0:';
    end;
  _tcp_signature:=_tcp_signature + IntToStr(DF) + ':';
  _p0f_signature:=_p0f_signature + IntToStr(DF) + ':';

  s:=_tcp_options;
  p:=pos('T', s);
  if p > 0 then
    _ettercap_signature:=_ettercap_signature + '1:'
  else
    _ettercap_signature:=_ettercap_signature + '0:';

  if _tcp_flags = 'S' then
    _ettercap_signature:=_ettercap_signature + 'S:'
  else
    begin
      if _tcp_flags = 'SA' then
        _ettercap_signature:=_ettercap_signature + 'A:';
    end;

  _ettercap_signature:=_ettercap_signature + IntToHex(ntohs(_ip.ip_totallength), 2);

  _tcp_signature:=_tcp_signature + IntToStr(ntohs(_ip.ip_totallength)) + ':';
  _p0f_signature:=_p0f_signature + IntToStr(ntohs(_ip.ip_totallength)) + ':';

  _tcp_signature:=_tcp_signature + _tcp_options;
  _p0f_signature:=_p0f_signature + _tcp_options;

  ip:=_ip_src;
  mac:=_ether_src;

{  host.Entry['lasttimeseen']:=FormatDateTime('HH:mm.ss mmm dd yyyy', UnixToDateTime(Header.ts.tv_sec, false));
  host.Entry['vlanid'] := _vlan_id;

  host.Entry['tcpconnectiontype'] := _tcp_flags;
  host.Entry['tcpsignature']      := _tcp_signature;
  host.Entry['p0fsignature']      := _p0f_signature;
  host.Entry['ettercapsignature'] := _ettercap_signature;

  if mtu <> 0 then
    begin
      host.Entry['mtu'] := IntToStr(mtu);
      host.Entry['tcplink'] := FindTCPOS5(IntToStr(mtu));
    end; }
    
  tcpfp:='';
  ettercapfp:='';
  p0ffp:='';

  if info^.TCP = true then
    begin
      os := FindTCPOS(_tcp_flags, _tcp_signature);

      tcpfp:=ip + ';' + mac + ';TCP;' + os;
  
      if debug then
        tcpfp:=tcpfp + chr(10) + chr(9) + _tcp_flags + ';' + _tcp_signature;
    end;
    
  if info^.Ettercap then
    begin
      os := FindEttercapOS(_ettercap_signature);

      ettercapfp:=ip + ';' + mac + ';Ettercap;' + os;

      if debug then
        ettercapfp:=ettercapfp + chr(10) + chr(9) + _tcp_flags + ';' + _ettercap_signature;
    end;

  if info^.p0f then
    begin
      if _tcp_flags = 'S' then
        os:=Findp0fsOS(_p0f_signature);
      if _tcp_flags = 'SA' then
        os:=Findp0fsaOS(_p0f_signature);

      p0ffp:=ip + ';' + mac + ';p0f;' + os;

      if debug then
        p0ffp:=p0ffp + chr(10) + chr(9) + _tcp_flags + ';' + _p0f_signature;
    end;

  s:='';
  if tcpfp <> '' then
    s:=tcpfp;
  if ettercapfp <> '' then
    begin
      if s = '' then
        s:=ettercapfp
      else
        s:=s + chr(10) + ettercapfp;
    end;
  if p0ffp <> '' then
    begin
      if s = '' then
        s:=p0ffp
      else
        s:=s + chr(10) + p0ffp;
    end;
    
  result:=s;
end;



function ConstructTCPOptions(size:integer):boolean;
var
  len,
  offset,
  x:integer;
  buff:packetbuffer;
  odd, s:string;

begin
  result:=false;

  if not ConstructTCP(size) then exit;

  //zeroize things
  _tcp_options:='';
  for x:=0 to length(buff) - 1 do
    buff[x]:=0;

  len:=_tcp_hlen - sizeof(TCP_Header);  //get length of TCP Options
  if len > 0 then
    begin
      if _is_a_vlan then
        offset:=sizeof(EthernetII_Header) + sizeof(VLAN_Header) + _ip_hlen + sizeof(TCP_Header)
      else
        offset:=sizeof(EthernetII_Header) + _ip_hlen + sizeof(TCP_Header);
      move(_packet[offset], buff, len);
      _tcp_options:=DecodeTCPOptions(buff, len, true);

      //start check for odd features
      odd:='';
      len:=size - offset - len;
      if len > 0 then
        if _tcp_options[length(_tcp_options)-1] = 'E' then
          odd:=odd + 'P';

      if _ip.ip_id = 0 then
        odd:=odd + 'Z';

      if _ip_hlen > 20 then
        odd:=odd + 'I';

      if _ip_type = 'v4' then
        len:=ntohs(_ip.ip_totallength) - _tcp_hlen - _ip_hlen;

      if _ip_type = 'v6' then
        len:=ntohs(_ipv6.ip_payloadlength) - _tcp_hlen - _ip_hlen;

      if len > 0 then
        odd:=odd + 'D';

      if pos('U', _tcp_flags) > 0 then   //put in for thoroughness since p0f has it, but I'll catch this as an 'SU' packet or such already.
        odd:=odd + 'U';

      //"unused" field value, not sure what this in in p0f?

      if _tcp_flags = 'S' then
        begin
          if _tcp.tcp_ack <> 0 then
            odd:=odd + 'A';
        end
      else if _tcp_flags = 'SA' then
        begin
          if _tcp.tcp_ack <> 0 then
            odd:=odd + 'A';
        end;

      if _tcp_flags = 'S' then
        if _options_er <> 0 then
          odd:=odd + 'T';

      if _tcp_flags = 'SA' then
        if pos('T', _tcp_options) > 0 then
          odd:=odd + 'T';

      //look for 'unusual flags'
      s:=_tcp_flags;
      x:=pos('S', s);
      if x > 0 then
        delete(s, x, 1);
      x:=pos('A', s);
      if x > 0 then
        delete(s, x, 1);

      if s <> '' then
        odd:=odd + 'F';

      if odd = '' then
        _tcp_options:=_tcp_options + '.'
      else
        _tcp_options:=_tcp_options + odd;

    end;

  if _tcp_options = '' then exit;

  result:=true;
end;

//function by Bogdan Calin, got from him in another project...
function DecodeTCPOptions(var buff; size : Word; with_details : boolean) : String;
type
    TByteArray = Array[0..0] of Byte;
var
    done        : boolean;
    res         : String;
    details     : String;
    i, len      : integer;

begin
  //zeroize things
  res              := '';
  details          := '';
  _options_mss     := 0;
  _options_ts      := 0;
  _options_er      := 0;

  if  size > 0 then
    begin
      i    := 0;
      done := false;

      while not done do
        begin
          // check for a known option
          case TByteArray(buff)[i] of
            _TCP_OPTION_END :
              begin
                res := res + 'E,';
                i:=size;      //if you hit this this is supposed to mean End of Options, so we'll bail;  there may be useful/odd stuff, but....
              end;

          _TCP_OPTION_NOOP :
            begin
              res := res + 'N,';
              inc(i);
            end;

          _TCP_OPTION_MAX_SEG_SIZE :
            begin
              // compute MSS (Maximum Segment Size)
              Move(TByteArray(buff)[i+2], _options_mss, 2);
              _options_mss  := ntohs(_options_mss);

              res := res + 'M' + IntToStr(_options_mss) + ',';

              // jump to the next option
              i   := i + 4;
            end;

          _TCP_OPTION_WIN_SCALE :
            begin
              // compute Win Scale
              Move(TByteArray(buff)[i+2], _options_win, 1);

              res := res + 'W' + IntToStr(_options_win) + ',';

              i   := i + 3;
            end;

          _TCP_OPTION_SACK_OK  :
            begin
              res := res + 'S,';
              i   := i + 2;
            end;

          _TCP_OPTION_SACK :
            begin
              res := res + 'K,';
              len :=TByteArray(buff)[i+1];
              if len = 0 then len:=1; //something went wrong so lets at least increment it
              i   := i + len;
            end;

          _TCP_OPTION_ECHO :
            begin
              res := res + 'E,';
              i   := i + 6;
            end;

          _TCP_OPTION_ECHO_REPLY :
            begin
              // compute Echo Reply
              Move(TByteArray(buff)[i+2], _options_echo_reply, 4);
              _options_mss  := ntohl(_options_echo_reply);

              res := res + 'F' + IntToStr(_options_echo_reply) + ',';

              i   := i + 6;
            end;

          _TCP_OPTION_TIMESTAMP :
            begin
              // compute TS (TimeStamp)
              Move(TByteArray(buff)[i+2], _options_ts, 4);

              _options_ts := ntohl(_options_ts);

              res := res + 'T';
              if _options_ts = 0 then
                res := res + '0';
//              else
//                res := res + 'X';

              // compute ER (Echo reply)
              Move(TByteArray(buff)[i+2+4], _options_er, 4);

{              if _options_er = 0 then
                res := res + '0'
              else
                res := res + 'X';
}
              res:=res + ',';

              i   := i + 10;
            end;

          _TCP_OPTION_POCP :
            begin
              res := res + 'P,';
              i   := i + 2;
            end;

          _TCP_OPTION_POSP :
            begin
              res := res + 'R,';
              i   := i + 3;
            end;
          // unknown option ?
          else
            begin
              res := res + 'U,';
              len := TByteArray(buff)[i+1];
              if len = 0 then len:=1;  //just in case
              i   := i + len + 1;
            end;
          end;

          // check if we are done ...
          if (i >= size) or (i=0) then done := true;
          end;
     end;

  delete(res, length(res), 1);
  res:=res + ':';

  result := res;
end;



end.

