
rule m3e9_361e6a48c0000b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.361e6a48c0000b10"
     cluster="m3e9.361e6a48c0000b10"
     cluster_size="162"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['012569457337c73b82e9ebe9487dc6db','0237e7b3c44a6648228f514d9b500c53','0e1790b6ea2f0bbf322b10bd0797c3eb']"

   strings:
      $hex_string = { 004142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
