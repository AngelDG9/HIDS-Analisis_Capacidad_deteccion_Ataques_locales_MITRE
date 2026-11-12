-- WE0-2 (T4b) — re-export literal de las 5 acciones Command de la prueba WE0-2.
-- Fuente: ghosts.history_timeline (PostgreSQL del host, 127.0.0.1:5432).
-- La timeline se envió a desktop-btmcfa5 el 2026-11-12 10:00:49Z.
-- Filas esperadas: 7255, 7256, 7257, 7258, 7259 (5 filas).
-- No se filtra por texto: se seleccionan los ids exactos de la prueba.
select id, createdutc, handler, command
from history_timeline
where machineid = (select id from machines where name = 'desktop-btmcfa5')
  and id between 7255 and 7259
order by id;
