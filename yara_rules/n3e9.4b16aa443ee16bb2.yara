
rule n3e9_4b16aa443ee16bb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b16aa443ee16bb2"
     cluster="n3e9.4b16aa443ee16bb2"
     cluster_size="42"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte bundler archsms"
     md5_hashes="['0508e1ac06621298bdd13581ff922d26','0c9b49baf85a3adb0f0d4835a35bfd47','95bf03536c49295ee6181282a7fcf592']"

   strings:
      $hex_string = { 000102f011030421315105064161a11207718191c122130809b1d1327233b31435b57637e142522383447415f19253935464d456571819627324b44555751626 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
