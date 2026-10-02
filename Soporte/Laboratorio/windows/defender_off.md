# Windows Defender OFF — procedimiento y checklist (control ambiental)

> **Entregable E4 del bloque `fase-02b-diseno`.** **No se ha desactivado nada**: es el
> procedimiento que ejecutará el humano en `fase-02b-construccion`. Fuente: `plan.md` D3.

---

## 1. Por qué se desactiva (declaración)

Con Defender **activo**, la medición **no mide a Wazuh**:

1. **Cuarentena del artefacto** → el ataque no se ejecuta → **falso negativo**.
2. **Alertas propias de Defender** convertidas en "detecciones" (el manager ya trae
   `0600-win-wdefender_rules.xml`, **113 reglas**, y `0430-ms_wdefender`, 3) → inflaría el
   recuento **midiendo al antivirus**.
3. **Aislamiento/corrección a mitad de ventana** → contamina `[t0,t1]` y la doble iteración.

Se trata como **control ambiental declarado** (igual que "NAT desconectado" y
"detección-only"): queda escrito **qué se apagó, cómo y que se verificó antes de cada ventana**.

> **Objeto de medida = Wazuh.** Un ensayo con Defender **ON** es **trabajo futuro opcional**
> (comparar "Wazuh vs. antivirus nativo"), fuera del alcance de este laboratorio.

---

## 2. Procedimiento de desactivación (orden)

> El **orden importa**: primero **Tamper Protection**, si no, el sistema vuelve a encender
> sola la protección en tiempo real.

1. **Tamper Protection → OFF** (Seguridad de Windows → Protección antivirus y contra
   amenazas → Administrar la configuración → *Protección contra alteraciones*).
   *(Puede requerir edición vía directiva/GPO si la UI está bloqueada.)*
2. **Protección en tiempo real → OFF**.
3. **Protección en la nube (MAPS) → OFF** y **supervisión del comportamiento → OFF**.
4. **(Si aplica) Exclusión / desactivación de envío automático de muestras.**
5. **Sacar un snapshot** del estado con Defender off.

---

## 3. Verificación (ejecutar y anotar)

```powershell
# Estado del antivirus (Preference = 0 => desactivado)
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled, \
  BehaviorMonitorEnabled, IsTamperProtected

# Servicio de Defender
Get-Service WinDefend | Select-Object Status, StartType
```

Resultado esperado: `RealTimeProtectionEnabled = False`, `BehaviorMonitorEnabled = False`,
`IsTamperProtected = False`.

---

## 4. Checklist antes de **cada** ventana de ataque

- [ ] `Get-MpComputerStatus` muestra real-time **off**.
- [ ] **Tamper** off (`IsTamperProtected = False`).
- [ ] Nube/behavior off.
- [ ] Se anota **fecha/hora y cómo** se verificó.
- [ ] Si algo volvió a encenderse → **se apaga y se repite la verificación** antes de `t0`.

> **Riesgo declarado:** una actualización o un reinicio puede **reactivar** parte de Defender.
> Por eso la verificación es **previa a cada ventana**, no una sola vez.

---

## 5. Referencias

- Plan D3: `plan.md`.
- Reglas Windows de Defender activas: `Soporte/Wazuh/Configuracion/active_ruleset.txt`
  (`0600-win-wdefender`, 62100–62212; `0430-ms_wdefender`, 83000–83002).
- Pasos de montaje: `pasos_montaje.md`.
