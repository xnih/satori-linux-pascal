//http://users.adelphia.net/~rllibby/delphitips/tip4.html

unit TimeConversion;

interface

uses
  sysutils;

const
  SecsPerDay =  86400;


// Unix DateTime conversion functions
function UnixToDateTime(Value: Longword; InUTC: Boolean): TDateTime;
function UnixUTCToDateTime(Value: Longword): TDateTime;
function UnixLocalToDateTime(Value: Longword): TDateTime;
function DateTimeToUnix(Value: TDateTime; InUTC: Boolean): LongWord;
function DateTimeToUnixLocal(Value: TDateTime): LongWord;
function DateTimeToUnixUTC(Value: TDateTime): LongWord;

implementation

function UnixToDateTime(Value: Longword; InUTC: Boolean): TDateTime;
var dwValue: LongWord;
     Days: LongWord;
     Hour: Word;
     Min: Word;
     Sec: Word;
//     tz: TTimeZoneInformation;
begin

{  // Get time zone information
  GetTimeZoneInformation(tz);

  // Offset by time zone
  if InUTC then
     // UTC time
     dwValue:=Value
  else
     // Local time to UTC
     dwValue:=LongWord(Integer(Value) - (tz.Bias * 60));
}
dwValue:=value;

  // Decode days and time part
  Days:=dwValue div SecsPerDay;
  dwValue:=dwValue mod SecsPerDay;
  Hour:=dwValue div 3600;
  dwValue:=dwValue mod 3600;
  Min:=dwValue div 60;
  Sec:=dwValue mod 60;

  // Return encoded date time
  result:=EncodeDate(1970, 1, 1)+Days+EncodeTime(Hour, Min, Sec, 0);

end;

function UnixUTCToDateTime(Value: Longword): TDateTime;
begin

  // Convert unix UTC to date time
  result:=UnixToDateTime(Value, True);

end;

function UnixLocalToDateTime(Value: Longword): TDateTime;
begin

  // Convert unix local to date time
  result:=UnixToDateTime(Value, False);

end;

function DateTimeToUnix(Value: TDateTime; InUTC: Boolean): LongWord;
var Year: Word;
     Month: Word;
     Day: Word;
     Hour: Word;
     Min: Word;
     Sec: Word;
     MSec: Word;
//     tz: TTimeZoneInformation;
     Days: Integer;
begin

  // Decode date and time values
  DecodeDate(Value, Year, Month, Day);
  DecodeTime(Value, Hour, Min, Sec, MSec);

  // Get difference from Unix epoch of Jan 1, 1970 12:00 am
  Days:=Trunc(EncodeDate(Year, Month, Day)-EncodeDate(1970, 1, 1));

  // Get time zone information
//  GetTimeZoneInformation(tz);

  // Set result (number of seconds since Unix Epoch of Jan 1, 1970 GMT)
//  if InUTC then
     // UTC time
     result:=(Days * SecsPerDay) + (Hour * 3600) + (Min * 60) + Sec
//  else
     // Local time
//     result:=(Days * SecsPerDay) + (Hour * 3600) + (Min * 60) + Sec + (tz.Bias * 60);

end;

function DateTimeToUnixLocal(Value: TDateTime): LongWord;
begin

  // Get local unix time
  result:=DateTimeToUnix(Value, False);

end;

function DateTimeToUnixUTC(Value: TDateTime): LongWord;
begin

  // Get UTC unix time
  result:=DateTimeToUnix(Value, True);

end;

end.

