# NTO-InfoSec-2024-writeups
# Команда "two_raccoons_enough"
____
# Task based
## PWN


## Web 1
На сайте мы сразу же видим число 20, на которое можно нажать. Нажав мы видим 'Hint_1 maybe in etc/secret ???'.
Это явный намёк на LFI. Просто меняем путь в строке на http://192.168.12.10:5001/download?file_type=../../../../etc/secret и получаем флаг.
nto{P6t9_T77v6RsA1}
