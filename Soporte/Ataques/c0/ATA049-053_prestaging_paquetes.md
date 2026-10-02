# Tanda B — pre-staging de paquetes (dependencias offline GUI)

> Constancia **reproducible** del material pre-steado (§C.2 de
> `Soporte/Ataques/criterio_ataques.md`): **URL + `sha256`**. Entra **ANTES de `t0`**
> (fuera de `[t0,t1]`) y el revert lo elimina. **No contiene secretos.**
> Creado el **2026-10-02** (bloque `fase-03-p1-cierre`, tanda B).

## Paquetes GUI (Xvfb + x11-apps + xclip + xdotool + xinput)

Descargados en el **HOST** desde `archive.ubuntu.com` (Ubuntu noble) a partir del
árbol de dependencias de la víctima (`apt-get install --print-uris --no-install-recommends`),
resolviendo las **versiones actuales** contra el índice de Ubuntu. Instalados **offline** con
`dpkg -i` en la víctima. **49 paquetes**, ≈ **43.0 MiB**.

| Paquete | Versión | URL | `sha256` | bytes |
|---|---|---|---|---|
| `libdrm-intel1` | `2.4.125-1ubuntu0.1~24.04.2` | `http://archive.ubuntu.com/ubuntu/pool/main/libd/libdrm/libdrm-intel1_2.4.125-1ubuntu0.1~24.04.2_amd64.deb` | `847195765b9ef7e7886677aeae9987aa54e496758b4e6e5a4ed2cb580b252244` | 63868 |
| `libfontenc1` | `1:1.1.8-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libf/libfontenc/libfontenc1_1.1.8-1build1_amd64.deb` | `0c5d57211cac9659e7f4c856f5e1922c4a522fe8bcf5776e9707b2811f965702` | 13996 |
| `libgbm1` | `25.2.8-0ubuntu0.24.04.3` | `http://archive.ubuntu.com/ubuntu/pool/main/m/mesa/libgbm1_25.2.8-0ubuntu0.24.04.3_amd64.deb` | `62ba0e565a7cb546e952d8e33237589bda270370c3f977cd9f122ebb5f0bd288` | 34274 |
| `libgl1` | `1.7.0-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libg/libglvnd/libgl1_1.7.0-1build1_amd64.deb` | `e2b2fadeb883f073b566ad1d7874f6702397514d258473e96152a89d4d502a09` | 101990 |
| `libgl1-mesa-dri` | `25.2.8-0ubuntu0.24.04.3` | `http://archive.ubuntu.com/ubuntu/pool/main/m/mesa/libgl1-mesa-dri_25.2.8-0ubuntu0.24.04.3_amd64.deb` | `b1d555b865dea0fe3d6805103ed370cec5dac41300620bafeb5a404a71ff25cf` | 37948 |
| `libglvnd0` | `1.7.0-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libg/libglvnd/libglvnd0_1.7.0-1build1_amd64.deb` | `33f5e07c74f73c2bfb44086ae0f9e6da52acd6c104d30ffe8fd768d8253d5e82` | 69594 |
| `libglx-mesa0` | `25.2.8-0ubuntu0.24.04.3` | `http://archive.ubuntu.com/ubuntu/pool/main/m/mesa/libglx-mesa0_25.2.8-0ubuntu0.24.04.3_amd64.deb` | `309a621946c62be0d91b601119a9db54d20dddafeb6834d4de3478f43508fe05` | 110154 |
| `libglx0` | `1.7.0-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libg/libglvnd/libglx0_1.7.0-1build1_amd64.deb` | `aa4953182f30abde90cb5b072e83d7286b557b325769b8686196a7bd396d8795` | 38558 |
| `libice6` | `2:1.0.10-1build3` | `http://archive.ubuntu.com/ubuntu/pool/main/libi/libice/libice6_1.0.10-1build3_amd64.deb` | `ad1edb5303574fee154e487947177e5bd15363aa71b92f78f5a2a7145fdb81c5` | 41398 |
| `libllvm20` | `1:20.1.2-0ubuntu1~24.04.3` | `http://archive.ubuntu.com/ubuntu/pool/main/l/llvm-toolchain-20/libllvm20_20.1.2-0ubuntu1~24.04.3_amd64.deb` | `f018e71c72c7a4742fb1aff9dc98b45586f42e6ea464d4918af7e3772b7f0658` | 30574382 |
| `libpciaccess0` | `0.17-3ubuntu0.24.04.3` | `http://archive.ubuntu.com/ubuntu/pool/main/libp/libpciaccess/libpciaccess0_0.17-3ubuntu0.24.04.3_amd64.deb` | `87a3b1c2a09f54d229e5e1f5424adc806e8f99bbb8aa8c8dea114b727f7a5a96` | 19220 |
| `libpixman-1-0` | `0.42.2-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/p/pixman/libpixman-1-0_0.42.2-1build1_amd64.deb` | `d9c2931c4c424615eeab9dd5ae08bfc608b84e803c1d3ccddf319270db213421` | 279306 |
| `libsm6` | `2:1.2.3-1build3` | `http://archive.ubuntu.com/ubuntu/pool/main/libs/libsm/libsm6_1.2.3-1build3_amd64.deb` | `1d27ebc381b499075a28c504be4d7d424c63b6866354736ac7f8d25813860cdf` | 15684 |
| `libvulkan1` | `1.3.275.0-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/v/vulkan-loader/libvulkan1_1.3.275.0-1build1_amd64.deb` | `ccf4fe8f4461442f27ea2494c7ae650b60bd396fec2688b0c44a27d66a222f74` | 142010 |
| `libwayland-server0` | `1.22.0-2.1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/w/wayland/libwayland-server0_1.22.0-2.1build1_amd64.deb` | `edbfa4b6857691ae922cc768a753fab230eee9e956aa2ce4f2eaa8d9ad777dca` | 33928 |
| `libx11-xcb1` | `2:1.8.7-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libx11/libx11-xcb1_1.8.7-1build1_amd64.deb` | `7d0d357e47cd6e1042be34da1d37cea313420b000035e71e855087c8268ab127` | 7800 |
| `libxaw7` | `2:1.0.14-1build2` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxaw/libxaw7_1.0.14-1build2_amd64.deb` | `2a9cdc82ecf566de76e05394efc604c9cced49e12c28b10e1ca101062b47bac0` | 186984 |
| `libxcb-damage0` | `1.15-1ubuntu2` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxcb/libxcb-damage0_1.15-1ubuntu2_amd64.deb` | `d028756c2a2059c7f034c5e39a4a121c3664ddd39ff69feca04d99329bcbdf7f` | 4980 |
| `libxcb-dri3-0` | `1.15-1ubuntu2` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxcb/libxcb-dri3-0_1.15-1ubuntu2_amd64.deb` | `3d3d0e95e56ae16010a84883196b8153cba62d6831f9aaee2a68c46f20c7c004` | 7142 |
| `libxcb-glx0` | `1.15-1ubuntu2` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxcb/libxcb-glx0_1.15-1ubuntu2_amd64.deb` | `d07cde26c70fe92df7c327928371e495cc4570fed2d6518758a5db5715cb34c1` | 24774 |
| `libxcb-present0` | `1.15-1ubuntu2` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxcb/libxcb-present0_1.15-1ubuntu2_amd64.deb` | `2e36e6557e87dbfd64df3143cbf81a4f75c3447501a545b4730511d228b0dd17` | 5676 |
| `libxcb-randr0` | `1.15-1ubuntu2` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxcb/libxcb-randr0_1.15-1ubuntu2_amd64.deb` | `b5cb519823a05a617b543dc9b6a9289b7648b20048244abe021caa706309835a` | 17862 |
| `libxcb-shm0` | `1.15-1ubuntu2` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxcb/libxcb-shm0_1.15-1ubuntu2_amd64.deb` | `229d1280d459f1ba44c22939d3f9b61d9d20932d9a646b3fe4ce50be4cdf2325` | 5756 |
| `libxcb-sync1` | `1.15-1ubuntu2` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxcb/libxcb-sync1_1.15-1ubuntu2_amd64.deb` | `14286795a258593259923619073e50c15345673befae2733f7b0577b07359aa8` | 9312 |
| `libxcb-xfixes0` | `1.15-1ubuntu2` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxcb/libxcb-xfixes0_1.15-1ubuntu2_amd64.deb` | `0b2ab64af92a71e3d1a35e3c819880ee28d04bfac81360df68ae8d8e9663ebd2` | 10190 |
| `libxcursor1` | `1:1.2.1-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxcursor/libxcursor1_1.2.1-1build1_amd64.deb` | `1a4beee621454e42fe0d2f4e1633611126e43d891f0aec28e4a06744f6e9f04d` | 20748 |
| `libxdo3` | `1:3.20160805.1-5build1` | `http://archive.ubuntu.com/ubuntu/pool/universe/x/xdotool/libxdo3_3.20160805.1-5build1_amd64.deb` | `3506c2824a74255439813f824a1629387452d52c6efd6d7916b8b54e458175e8` | 22202 |
| `libxfixes3` | `1:6.0.0-2build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxfixes/libxfixes3_6.0.0-2build1_amd64.deb` | `0ee1015cccd063249e01c0cd0bf45f513c8ac9a1e5e485070c12e69192455e4a` | 10764 |
| `libxfont2` | `1:2.0.6-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxfont/libxfont2_2.0.6-1build1_amd64.deb` | `1d5653c395f17f48473fce56cdab30eed16aac017359e6d2c34bc402d85197a0` | 93028 |
| `libxft2` | `2.3.6-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/x/xft/libxft2_2.3.6-1build1_amd64.deb` | `b4f4f3255c0b8773b260c61cbe20ee7c63799cfc0e4e389fa58375dd480b093a` | 45280 |
| `libxi6` | `2:1.8.1-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxi/libxi6_1.8.1-1build1_amd64.deb` | `0ea7acb5e8a8ce4d6653b30e03a319bfe136db7bfb5ee7cad34c2aa1272ea8d9` | 32404 |
| `libxinerama1` | `2:1.1.4-3build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxinerama/libxinerama1_1.1.4-3build1_amd64.deb` | `c8c93a3efdbb06e314f41bf48af4ca3652e4a3826bab5b9e00887660e619f239` | 6396 |
| `libxkbfile1` | `1:1.1.0-1build4` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxkbfile/libxkbfile1_1.1.0-1build4_amd64.deb` | `22ac5b7dca740e606261cebdfaf1a07738e92ad3d123570694374ddb4d5afea2` | 70010 |
| `libxmu6` | `2:1.1.3-3build2` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxmu/libxmu6_1.1.3-3build2_amd64.deb` | `05c13bce0e9a80139dfa72cc8e7a695b4f7d58b1884423929eade62179d99853` | 47610 |
| `libxrandr2` | `2:1.5.2-2build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxrandr/libxrandr2_1.5.2-2build1_amd64.deb` | `f2955a5e594f5724b58ad241d9231ea191cb36574a0d5e5ca6b661cd41d6256d` | 19670 |
| `libxrender1` | `1:0.9.10-1.1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxrender/libxrender1_0.9.10-1.1build1_amd64.deb` | `d70bd831aebe8d4834b5dd2ed98df26dd6bd27f1042c47543bd7f66df1ae22ea` | 19016 |
| `libxshmfence1` | `1.3-1build5` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxshmfence/libxshmfence1_1.3-1build5_amd64.deb` | `bc6de4bfaf9050a8ba83d4bcfb114131b081084a7972c03417f8523d52b5c742` | 4764 |
| `libxt6t64` | `1:1.2.1-1.2build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxt/libxt6t64_1.2.1-1.2build1_amd64.deb` | `2e4317d5ae1a45e517771ea0b8d93519b5f915ab08983facecd480d64dbd1489` | 170810 |
| `libxtst6` | `2:1.2.3-1.1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxtst/libxtst6_1.2.3-1.1build1_amd64.deb` | `632d74c760f0a4e844c499e7bc1eca4c709aa096fde783a7a6807604aef77545` | 12642 |
| `libxxf86vm1` | `1:1.1.4-1build4` | `http://archive.ubuntu.com/ubuntu/pool/main/libx/libxxf86vm/libxxf86vm1_1.1.4-1build4_amd64.deb` | `48b2799f52b86505d2bc91dcb1bfa6536545635b9849cb693d274d934116a8da` | 9282 |
| `mesa-libgallium` | `25.2.8-0ubuntu0.24.04.3` | `http://archive.ubuntu.com/ubuntu/pool/main/m/mesa/mesa-libgallium_25.2.8-0ubuntu0.24.04.3_amd64.deb` | `07c2a899c33a0ad7a66c90a32ae581f520e19ca644684e2e8470c48c3d37d2bf` | 10783430 |
| `x11-apps` | `7.7+11build3` | `http://archive.ubuntu.com/ubuntu/pool/main/x/x11-apps/x11-apps_7.7+11build3_amd64.deb` | `e81cbe75a3e46797bba360205d0ecb45809959c0137b52fda47d321fc556149b` | 709312 |
| `x11-common` | `1:7.7+23ubuntu3` | `http://archive.ubuntu.com/ubuntu/pool/main/x/xorg/x11-common_7.7+23ubuntu3_all.deb` | `b545fa5196dd7467ba3770d6ce575abcd7941071961ea9f7535a319d9d20fd46` | 21748 |
| `x11-xkb-utils` | `7.7+8build2` | `http://archive.ubuntu.com/ubuntu/pool/main/x/x11-xkb-utils/x11-xkb-utils_7.7+8build2_amd64.deb` | `69df4191e165f8b89d067f6234fcce89a4923d27d1e66dd92e6d63d6da93cdb0` | 170314 |
| `xclip` | `0.13-3` | `http://archive.ubuntu.com/ubuntu/pool/universe/x/xclip/xclip_0.13-3_amd64.deb` | `bb98b6b3c9f7338f1e1e7b56aad3c7dfec0f1b6032bda9546061c2469aa93910` | 17586 |
| `xdotool` | `1:3.20160805.1-5build1` | `http://archive.ubuntu.com/ubuntu/pool/universe/x/xdotool/xdotool_3.20160805.1-5build1_amd64.deb` | `58a202c74bce31ca2d72d4d514942a5ab6191932696adc5d21d909c9216b13cb` | 42556 |
| `xinput` | `1.6.4-1build1` | `http://archive.ubuntu.com/ubuntu/pool/main/x/xinput/xinput_1.6.4-1build1_amd64.deb` | `9bdea92f6f257982a7c0c06fa0b2b40e15ab53350445bb830e7991f65a2a2512` | 28946 |
| `xserver-common` | `2:21.1.12-1ubuntu1.8` | `http://archive.ubuntu.com/ubuntu/pool/main/x/xorg-server/xserver-common_21.1.12-1ubuntu1.8_all.deb` | `5720e7995c3b546927046f63bb4a344773b27850379c4b2694edf279025ad772` | 34794 |
| `xvfb` | `2:21.1.12-1ubuntu1.8` | `http://archive.ubuntu.com/ubuntu/pool/universe/x/xorg-server/xvfb_21.1.12-1ubuntu1.8_amd64.deb` | `712429d9342c7d6cef63afb33ccfcd2bd477a69371b5c9941a9c6dde31a4cd3c` | 876860 |

## Cliente de nube `rclone` (ATA049)

| Fichero | URL | `sha256` | bytes |
|---|---|---|---|
| `rclone-v1.75.1-linux-amd64.zip` (contiene `rclone`) | `https://downloads.rclone.org/v1.75.1/rclone-v1.75.1-linux-amd64.zip` | `982b5aa772841168f8e380f139e9e787b2a105403e32b94da8676a0e1c0a13ab` | 31470505 |

## Resultado de la instalación (verificado en la víctima, 2026-10-02)

```text
dpkg_rc=0 (sin dependencias pendientes; `apt-get install -f` -> 0 nuevos)
Xvfb=/usr/bin/Xvfb  xwd=/usr/bin/xwd  xwud=/usr/bin/xwud
xclip=/usr/bin/xclip  xdotool=/usr/bin/xdotool  xinput=/usr/bin/xinput
comprobación funcional: xwd captura 4 MiB; xclip round-trip OK;
                        xinput test-xi2 captura KeyPress de xdotool OK
```

## Alcance declarado

Instalación **offline** de paquetes fijados (URL+`sha256`); **sin NAT**. Es pre-staging §C:
el material entra **antes de `t0`** y el revert de la víctima lo elimina. El mecanismo de
las 3 técnicas GUI queda **factible offline**.

