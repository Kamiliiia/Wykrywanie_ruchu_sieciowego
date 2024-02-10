Ten skrypt Pythona służy jako sniffer pakietów sieciowych. Wykorzystuje bibliotekę Scapy do przechwytywania pakietów IPv4 i IPv6. Każdy przechwycony pakiet jest przekazywany do funkcji packet_callback, która analizuje pakiet i wyodrębni kluczowe informacje, takie jak adresy IP, porty, protokoły i nazwy hostów.

Skrypt obsługuje protokoły ICMP, TCP i UDP. Dla pakietów TCP, jeśli port docelowy to 80, skrypt identyfikuje protokół jako HTTP, a jeśli port docelowy to 443, skrypt identyfikuje protokół jako HTTPS. Dla pakietów UDP, skrypt po prostu wyodrębnia porty źródłowe i docelowe.

Skrypt jest wielowątkowy, co oznacza, że może przechwytywać pakiety IPv4 i IPv6 jednocześnie. Przechwytywanie pakietów można zatrzymać, ustawiając flagę stop_threads na True.

Ten skrypt jest przydatny dla osób, które chcą monitorować ruch sieciowy na swoim komputerze lub sieci, a także dla osób, które chcą nauczyć się więcej o pakietach sieciowych i protokołach sieciowych.

**Użycie**
Uruchom skrypt Pythona sniffer.py:
python sniffer.py

Skrypt zacznie przechwytywać pakiety IPv4 i IPv6. Domyślnie przechwytuje 10 pakietów każdego typu, ale możesz zmienić tę liczbę w kodzie.

Aby zatrzymać przechwytywanie pakietów, ustaw zmienną stop_threads na True w kodzie.

**Obsługiwane protokoły**
Obecnie skrypt obsługuje następujące protokoły:

ICMP
TCP (w tym HTTP i HTTPS rozpoznawane na podstawie portów)
UDP
