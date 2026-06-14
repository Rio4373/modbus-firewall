# 3.4. Тестирование решения

## Краткая сводка сценариев

| Сценарий | Цель | Фактический результат | Статус |
| --- | --- | --- | --- |
| T1 | Подтвердить пропуск штатного чтения в режиме анализа | 3 запроса FC03 прошли, события сохранены в SQLite | Успешно |
| T2 | Подтвердить накопление повторяющейся записи в режиме анализа | 10 запросов FC06 по адресу 12 прошли и записаны в историю | Успешно |
| T3 | Подтвердить фиксацию редкой записи без включения в policy | 1 запрос FC16 по диапазону 80-81 записан в историю, но не вошёл в policy | Успешно |
| T4 | Сформировать policy по накопленной истории | Сгенерирована candidate policy, replay показал 1 непокрытую редкую запись | Успешно |
| T5 | Проверить разрешённое чтение в режиме фильтрации | Штатное чтение прошло, firewall зафиксировал совпадение с правилом | Успешно |
| T6 | Проверить разрешённую повторяющуюся запись в режиме фильтрации | Повторяющаяся запись по адресу 12 прошла, firewall указал matched_rule_id | Успешно |
| T7 | Проверить блокировку запрещённой записи | Клиент получил Modbus exception, значение регистра 50 на PLC не изменилось | Успешно |
| T8 | Проверить hot reload без рестарта | Операция, ранее блокировавшаяся, после обновления policy прошла при неизменном PID | Успешно |
| T9 | Оценить устойчивость при серии запросов | Обработано 3003 запросов, ошибок и обрывов соединения не зафиксировано | Успешно |
| T10 | Проверить обновление policy во время активного трафика | Во время 600 фоновых запросов выполнен hot reload без перезапуска и без ошибок | Успешно |

## Детализация сценариев

### T1. Штатное чтение регистров в режиме анализа

- Идентификатор сценария: T1
- Цель: подтвердить, что firewall в режиме `observe` не блокирует штатное чтение и сохраняет событие в историю.
- Входные данные: сценарий `arm-sim --scenario normal-read`; 3 запроса FC03 к диапазонам 0-1, 10-11, 20-21.
- Ожидаемый результат: все ответы успешны, в журнале firewall есть признаки принятия запроса, пропуска и сохранения события; в SQLite появляются записи.
- Фактический результат: все 3 операции завершились статусом `OK`; в журнале firewall присутствуют строки `запрос принят`, `observe: запрос пропущен`, `событие сохранено в storage`; события записаны в SQLite.
- Статус: Успешно.
- Артефакты: [клиент](../02_analysis_mode/t1_normal_read_client.log), [firewall](../02_analysis_mode/t1_normal_read_firewall.log), [plc-sim](../02_analysis_mode/t1_normal_read_plc.log), [выборка из БД](../02_analysis_mode/events_sample.tsv).

### T2. Повторяющаяся запись одного и того же адреса в режиме анализа

- Идентификатор сценария: T2
- Цель: накопить повторяющуюся write-операцию для автоматического включения в policy.
- Входные данные: сценарий `arm-sim --scenario repeated-write --repeat 10`; 10 запросов FC06 по адресу 12.
- Ожидаемый результат: все запросы проходят, события сохраняются в SQLite.
- Фактический результат: 10 запросов завершились статусом `OK`; в SQLite зафиксированы 10 событий FC06 по адресу 12.
- Статус: Успешно.
- Артефакты: [клиент](../02_analysis_mode/t2_repeated_write_client.log), [firewall](../02_analysis_mode/t2_repeated_write_firewall.log), [plc-sim](../02_analysis_mode/t2_repeated_write_plc.log), [агрегированная статистика событий](../02_analysis_mode/events_grouped_after_observe.tsv).

### T3. Редкая запись, остающаяся в истории, но не попадающая в политику

- Идентификатор сценария: T3
- Цель: подтвердить, что единичная write-операция сохраняется в истории, но не проходит фильтр порога K при генерации policy.
- Входные данные: сценарий `arm-sim --scenario rare-write`; 1 запрос FC16 к диапазону 80-81.
- Ожидаемый результат: операция проходит в `observe`, сохраняется в SQLite, но затем не включается в candidate policy.
- Фактический результат: запрос завершился статусом `OK`, событие сохранено; в candidate policy правило для FC16 диапазона 80-81 отсутствует.
- Статус: Успешно.
- Артефакты: [клиент](../02_analysis_mode/t3_rare_write_client.log), [firewall](../02_analysis_mode/t3_rare_write_firewall.log), [plc-sim](../02_analysis_mode/t3_rare_write_plc.log), [отчёт по формированию policy](../03_policy_generation/policy_generation_report.md).

### T4. Переход к формированию политики

- Идентификатор сценария: T4
- Цель: подтвердить автоматическое построение разрешающей policy по накопленной истории и анализ её покрытия.
- Входные данные: SQLite история из 14 событий после T1-T3; порог write-операций K=2.
- Ожидаемый результат: candidate policy создаётся автоматически, baseline policy сохраняется, replay показывает, какие операции покрыты и какие нет.
- Фактический результат: сформированы файлы policy; replay показал total=14, covered=13, blocked=1; единственной непокрытой операцией осталась редкая запись FC16.
- Статус: Успешно.
- Артефакты: [исходные события](../03_policy_generation/observed_events_input.tsv), [candidate policy](../03_policy_generation/policy.candidate.yaml), [generated policy](../03_policy_generation/policy.generated.yaml), [CLI генератора](../03_policy_generation/generate_policy_cli.log), [CLI replay](../03_policy_generation/replay_cli.log), [replay-report](../03_policy_generation/replay-report.json), [краткий отчёт](../03_policy_generation/policy_generation_report.md).

### T5. Разрешённое чтение проходит в режиме фильтрации

- Идентификатор сценария: T5
- Цель: подтвердить отсутствие ложной блокировки штатного чтения после перехода в `enforce`.
- Входные данные: активирована candidate policy; сценарий `normal-read`.
- Ожидаемый результат: чтение проходит, firewall фиксирует совпадение с allow-правилом.
- Фактический результат: все операции завершились статусом `OK`; в firewall журнале присутствует строка `запрос разрешен политикой` с `matched_rule_id`.
- Статус: Успешно.
- Артефакты: [переключение в enforce](../04_filtering_mode/activate_enforce_firewall.log), [клиент](../04_filtering_mode/t5_allowed_read_client.log), [firewall](../04_filtering_mode/t5_allowed_read_firewall.log), [plc-sim](../04_filtering_mode/t5_allowed_read_plc.log).

### T6. Повторяющаяся запись, попавшая в policy, проходит

- Идентификатор сценария: T6
- Цель: подтвердить, что автоматически сформированная policy пропускает типовую write-операцию без прерывания обмена.
- Входные данные: активная policy после T4; сценарий `repeated-write --repeat 3`.
- Ожидаемый результат: все операции проходят, firewall фиксирует совпадение с правилом разрешения записи.
- Фактический результат: 3 операции FC06 завершились статусом `OK`; в журнале firewall присутствует `matched_rule_id` для разрешённой записи.
- Статус: Успешно.
- Артефакты: [клиент](../04_filtering_mode/t6_allowed_repeated_write_client.log), [firewall](../04_filtering_mode/t6_allowed_repeated_write_firewall.log), [plc-sim](../04_filtering_mode/t6_allowed_repeated_write_plc.log).

### T7. Запрещённая запись блокируется и клиент получает Modbus exception

- Идентификатор сценария: T7
- Цель: подтвердить блокировку операции, отсутствующей в active policy, и доказать, что запрос не дошёл до PLC.
- Входные данные: сценарий `forbidden-write`; FC06 запись по адресу 50.
- Ожидаемый результат: firewall блокирует запрос, клиент получает Modbus exception, значение регистра 50 на PLC не меняется.
- Фактический результат: клиент получил `BLOCKED/EXCEPTION`; в firewall журнале зафиксировано `запрос заблокирован политикой`; значение регистра 50 до запроса равно 0, после запроса также равно 0.
- Статус: Успешно.
- Артефакты: [клиент](../04_filtering_mode/t7_blocked_forbidden_write_client.log), [firewall](../04_filtering_mode/t7_blocked_forbidden_write_firewall.log), [значение регистра до](../04_filtering_mode/t7_register_50_before.txt), [значение регистра после](../04_filtering_mode/t7_register_50_after.txt), [доказательство недостижения PLC](../04_filtering_mode/t7_block_proof.txt).

### T8. Обновление policy без перезапуска службы

- Идентификатор сценария: T8
- Цель: подтвердить горячее обновление активной policy и изменение поведения firewall без рестарта процесса.
- Входные данные: новая policy с дополнительным allow-правилом для FC06 по адресу 50; повторный запуск сценария `forbidden-write`.
- Ожидаемый результат: до обновления операция блокируется, после обновления проходит; PID firewall не меняется.
- Фактический результат: до обновления клиент получал exception, после обновления операция завершилась статусом `OK`; PID в файлах [до](../05_hot_reload/t8_firewall_pid_before.txt) и [после](../05_hot_reload/t8_firewall_pid_after.txt) совпадает; значение регистра 50 на PLC после обновления изменилось на 9999.
- Статус: Успешно.
- Артефакты: [клиент до обновления](../05_hot_reload/t8_before_update_client.log), [новая policy](../05_hot_reload/t8_policy_candidate.yaml), [validate-policy](../05_hot_reload/t8_validate_policy.log), [apply-policy](../05_hot_reload/t8_apply_policy.log), [hot reload в firewall](../05_hot_reload/t8_firewall_reload.log), [клиент после обновления](../05_hot_reload/t8_after_update_forbidden_write_client.log), [значение регистра после](../05_hot_reload/t8_register_50_after.txt), [проверка отсутствия рестарта](../05_hot_reload/t8_restart_check.txt), [plc-sim](../05_hot_reload/t8_after_update_forbidden_write_plc.log).

### T9. Серия штатных запросов для оценки устойчивости работы

- Идентификатор сценария: T9
- Цель: оценить устойчивость работы firewall при серии из нескольких тысяч штатных запросов.
- Входные данные: один прогон `normal-read` и один прогон `repeated-write --repeat 3000`.
- Ожидаемый результат: все запросы обрабатываются без неожиданной ошибки, без обрыва соединения и без рестарта firewall.
- Фактический результат: отправлено 3003 запросов; успешно обработано 3003; заблокировано 0; неожиданные ошибки 0; обрывы соединения 0; PID firewall не изменился.
- Статус: Успешно.
- Артефакты: [клиент normal-read](../06_stability/t9_normal_read_client.log), [клиент repeated-write](../06_stability/t9_repeated_write_load_client.log), [firewall normal-read](../06_stability/t9_normal_read_firewall.log), [firewall repeated-write](../06_stability/t9_repeated_write_load_firewall.log), [метрики JSON](../06_stability/t9_metrics.json), [отчёт по устойчивости](../06_stability/t9_report.md).

### T10. Обновление policy во время работы при активном трафике

- Идентификатор сценария: T10
- Цель: подтвердить применение новой policy во время активного штатного трафика без прерывания обмена.
- Входные данные: фоновые 200 прогонов `normal-read` и hot reload policy с добавлением allow-правила для `rare-write`.
- Ожидаемый результат: фоновые чтения продолжают проходить без ошибок, policy перечитывается без рестарта, после обновления `rare-write` проходит.
- Фактический результат: на фоне 600 штатных запросов выполнен hot reload; успешно обработано 600, ошибок 0, обрывов соединения 0; PID firewall не изменился; после обновления `rare-write` завершился статусом `OK`.
- Статус: Успешно.
- Артефакты: [фоновый трафик](../05_hot_reload/t10_background_normal_read.log), [метрики фонового трафика](../05_hot_reload/t10_background_metrics.json), [отчёт по фоновому трафику](../05_hot_reload/t10_background_report.md), [новая policy](../05_hot_reload/t10_policy_candidate.yaml), [apply-policy](../05_hot_reload/t10_apply_policy.log), [журнал firewall во время трафика](../05_hot_reload/t10_firewall_reload_and_traffic.log), [клиент rare-write после обновления](../05_hot_reload/t10_rare_write_after_update_client.log).

## Файлы, пригодные для вставки в текст ВКР

### Рисунки

- [../02_analysis_mode/t1_normal_read_firewall.log](../02_analysis_mode/t1_normal_read_firewall.log) — фрагмент журнала firewall в режиме анализа.
- [../04_filtering_mode/t7_blocked_forbidden_write_client.log](../04_filtering_mode/t7_blocked_forbidden_write_client.log) — вывод клиента при получении Modbus exception.
- [../05_hot_reload/t8_firewall_reload.log](../05_hot_reload/t8_firewall_reload.log) — фрагмент журнала hot reload без рестарта.
- [../05_hot_reload/t10_firewall_reload_and_traffic.log](../05_hot_reload/t10_firewall_reload_and_traffic.log) — hot reload при активном трафике.

### Таблицы

- [../02_analysis_mode/events_grouped_after_observe.tsv](../02_analysis_mode/events_grouped_after_observe.tsv) — агрегированные события наблюдаемого трафика.
- [../03_policy_generation/replay-report.json](../03_policy_generation/replay-report.json) — показатели покрытия candidate policy.
- [../06_stability/t9_report.md](../06_stability/t9_report.md) — сводные метрики устойчивости.

### Листинги

- [../03_policy_generation/policy.candidate.yaml](../03_policy_generation/policy.candidate.yaml) — автоматически сформированная policy.
- [../05_hot_reload/t8_policy_candidate.yaml](../05_hot_reload/t8_policy_candidate.yaml) — policy после расширения правил для hot reload.
- [../01_environment/manual_reproduction_commands.md](../01_environment/manual_reproduction_commands.md) — команды ручного воспроизведения испытаний.

## Готовые подписи к материалам

### Подписи к рисункам

- Рисунок — Журнал межсетевого экрана в режиме анализа Modbus TCP трафика с фиксацией принятия запроса, его пропуска и сохранения события в историю.
- Рисунок — Результат попытки выполнения запрещённой Modbus TCP операции, при которой клиент получил Modbus exception, сформированный межсетевым экраном.
- Рисунок — Журнал межсетевого экрана при горячем обновлении активной политики без перезапуска процесса службы.
- Рисунок — Применение обновлённой политики межсетевого экрана во время активного технологического обмена.

### Подписи к таблицам

- Таблица — Агрегированный состав Modbus TCP операций, накопленных в истории на этапе наблюдения.
- Таблица — Результаты replay-анализа покрытия автоматически сформированной политики по историческим событиям.
- Таблица — Показатели устойчивости межсетевого экрана при серии штатных Modbus TCP запросов.

### Подписи к листингам

- Листинг — Автоматически сформированная разрешающая политика межсетевого экрана на основе накопленной истории Modbus TCP запросов.
- Листинг — Обновлённая версия активной политики, применённая механизмом hot reload.
- Листинг — Команды ручного воспроизведения экспериментов по тестированию прототипа межсетевого экрана.
