unit generaltypes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils; 
  
type
  pDLLInfo = ^TDLLInfo;
  TDLLInfo = record
    DHCPIgnoreType:boolean;
    UseAny:boolean;
    ARPTrackAll:boolean;
    TCP:boolean;
    Ettercap:boolean;
    p0f:boolean;
  end;
  
implementation

end.

