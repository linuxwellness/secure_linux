
rule n3f0_231b11ba97a39916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.231b11ba97a39916"
     cluster="n3f0.231b11ba97a39916"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira vuxpjoji icgh"
     md5_hashes="['059b02cee4df3c7b3129b67fb2d8af80','0bf8fbfa1bafefa927873534b556f07d','fb828edee8fc0cc17dcdde7b450e1f67']"

   strings:
      $hex_string = { 3dc55d3b8b9e925a0d65170c7581867576c9484d65ccc6910ea6aea019e3a346bcdd8ddef99dfbeb7eaa51436fc6df8ce980c947ba93a841bf3cd5a6cfff491f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
