# Сборка и запуск программы
```
git clone https://github.com/borzor/Anti-Reversing_Technique
cd Anti-Reversing_Technique
cmake ./CMakeLists.txt 
cmake --build .
sudo ./ ...
```

## Используемые методы против отладки
### CMAKE FLAGS:
* Флаг ```-s``` заставит компилятор *удалить все таблицы символов(.symtab) и информацию о 
перемещении из исполняемого файла*.
* Флаг ```-fvisibility=hidden``` по умолчанию скрывает все возможные символы
из динамической таблицы символов .dymsym
* Флаг ```-О3``` является вторым по оптизимации(после -Ofast), но при этом более предпочтительным
из-за того, что некоторые оптизимации могут значительно увеличить бинарный файл в размерах
* Флаг ```-funroll-loops``` отменяет *сворачивание* структур циклов
* Флаг ```-static```  предотвращает линковку с динамическими библеотеками

### Техники используемые в коде
* Техника раннего возврата заключается в пуше адреса в стэк и мнговенного возврата. 
Это приведет к тому, что программа вернется на адрес в стэке. Важный момент, для того, чтобы определенный выше флаг ```-O3```
своей оптимизацией не испортил программу, необходимо определить низкий уровень оптимизации флагом ```-O1```.
* Прыжок на *недопустимый* байт
GDB дизасемблирует последовательно. Зная это, можно спрятать необходимую нам инструкци 
путем добавления дополнительных байтов, которые не будут выполнены, но GDB будет рассматривать это
как допустимый код.
* Метод отладки при помощи дочернего процесса  ```fork()``` создает дочерний процесс, который становится трасером родительского и 
автоматически начинает трайсить любые *форки* которые создает программа. Никто не может просто присоеденится к основному процессу, после того как за ним
начал трассировку его дочерний процесс.(Только 1 трассировщик может одновременно управлять отслежевыемым объектом!). 
Так же можно добавить флаг PTRACE_O_EXITKILL, который будет отправлять сигнал SIGKILL для всех трейсов, если трейсер был убит. 
* Проверка "TracerPid" поля в /proc/self/status файле. Если значение не ноль, значит к процессу прикреплен дебагер. 
Если это так, подаем сигнал родительскому сигналу и выходим.
* Проверка перед ```main()``` при помощи ```contructor``` attribute будет вызвана перед функцией ```main()```, для того чтобы исключить случаи, GDB 
запустит основную программу до того как дочерний процесс обнаружит дебагер и убьет программу. 