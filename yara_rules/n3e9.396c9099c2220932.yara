
rule n3e9_396c9099c2220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.396c9099c2220932"
     cluster="n3e9.396c9099c2220932"
     cluster_size="2200"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lethic strictor orbus"
     md5_hashes="['003269b9995d6c24e50cb59ab8cf28c4','00510ed935db94a14902270e286c23c1','0527c62e0d0a0e0df792923421909b1e']"

   strings:
      $hex_string = { 3f003000008800000010301f302c3036304d305730673071308b309230a230ad30c630cd30de30e5300331133122312c3143314d315c31693176318c31a231ac }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
