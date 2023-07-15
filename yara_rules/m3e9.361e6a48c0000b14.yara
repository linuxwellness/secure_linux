
rule m3e9_361e6a48c0000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.361e6a48c0000b14"
     cluster="m3e9.361e6a48c0000b14"
     cluster_size="115"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce emailworm"
     md5_hashes="['14100f5b4d6f2191d4296e157a62ef22','27952c1132c21442b9fe86541385893f','ac2eb0301e8244c5412cfa854f14d10e']"

   strings:
      $hex_string = { 004142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
