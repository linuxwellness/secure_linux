
rule j3e7_7094d6c348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7094d6c348000330"
     cluster="j3e7.7094d6c348000330"
     cluster_size="135"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos skymobi"
     md5_hashes="['0125aa02bc3b1ba4762ab9d715509182','01fe44216ec5388e2710efa21eda9a40','2113e29ee160b18a70675f000a437e16']"

   strings:
      $hex_string = { 01620009636c6173734e616d650005636c6f7365001563757272656e74416374697669747954687265616400066578697374730007666f724e616d6500036765 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
