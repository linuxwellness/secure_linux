
rule m3e9_611e97a9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611e97a9ca000b32"
     cluster="m3e9.611e97a9ca000b32"
     cluster_size="242"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['03e85aa637c939f8ff9dce8df21c5deb','0775bf2ebc25486cf4b47eb42c3b9143','434fd9405f1b35bd0b66819a7210b247']"

   strings:
      $hex_string = { d3eec8d43db62622e640a2aafdd6d97e5ff93ef41d0f52dd773efbac362abfb14f20f0430dc99156199f5df2d742c40e4e2eea063a00be72012d73aff71a68ad }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
