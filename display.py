
import curses
import hunter


def create_screen():
    # Create screen instance
    stdscr = curses.initscr()
    # Add color functionality
    curses.start_color()
    # Prevent key echoing
    curses.noecho()
    # No need to press enter to execute a command
    curses.cbreak()
    # Hide cursor
    curses.curs_set(False)

    return stdscr


# Display main screen
def display_screen(stdscr, counter, yara_results, port_number):

    stdscr.clear()

    y, x = stdscr.getmaxyx()
    y += 28
    x += 28
    # Create color pairs (background and foreground)
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)

    from curses.textpad import rectangle
    curses.textpad.rectangle(stdscr, 5, 0, 15, int(y + 8))
    curses.textpad.rectangle(stdscr, 5, int(y + 9), 15, int(y + 25))
    curses.textpad.rectangle(stdscr, 16, 0, 20, int(y + 25))

    stdscr.addstr(5, 1, 'Network Attacks', curses.A_BOLD)
    stdscr.addstr(5, int(y + 11), 'Ports Monitor', curses.A_BOLD)
    stdscr.addstr(16, 1, 'Detected YARA Rules', curses.A_BOLD)

    stdscr.addstr(7, 1, 'Ping Sweep    :         ', curses.color_pair(2))
    stdscr.addstr(8, 1, 'UDP Port Scan :        ', curses.color_pair(2))
    stdscr.addstr(9, 1, 'TCP Port Scan :         ', curses.color_pair(2))
    stdscr.addstr(10, 1, 'TCP NULL Scan :         ', curses.color_pair(2))
    stdscr.addstr(11, 1, 'TCP Xmas Scan :         ', curses.color_pair(2))
    stdscr.addstr(12, 1, 'TCP FIN Scan  :         ', curses.color_pair(2))
    stdscr.addstr(13, 1, 'SYN Flood     :         ', curses.color_pair(2))

    if counter['pingSweep'] > 0:
        stdscr.addstr(7, int(y), str(counter['pingSweep']), curses.color_pair(1))
    else:
        stdscr.addstr(7, int(y), str(counter['pingSweep']))
    if counter['unreachable'] > 0:
        stdscr.addstr(8, int(y), str(counter['unreachable']), curses.color_pair(1))
    else:
        stdscr.addstr(8, int(y), str(counter['unreachable']))
    if counter['portScan'] > 0:
        stdscr.addstr(9, int(y-3), str('DETECTED'), curses.color_pair(1))
    else:
        stdscr.addstr(9, int(y), str('-'))
    if counter['null'] > 0:
        stdscr.addstr(10, int(y), str(counter['null']), curses.color_pair(1))
    else:
        stdscr.addstr(10, int(y), str(counter['null']))
    if counter['xmas'] > 0:
        stdscr.addstr(11, int(y), str(counter['xmas']), curses.color_pair(1))
    else:
        stdscr.addstr(11, int(y), str(counter['xmas']))
    if counter['fin'] > 0:
        stdscr.addstr(12, int(y), str(counter['fin']), curses.color_pair(1))
    else:
        stdscr.addstr(12, int(y), str(counter['fin']))
    if counter['synFlood'] > 0:
        stdscr.addstr(13, int(y-3), str('DETECTED'), curses.color_pair(1))
    else:
        stdscr.addstr(13, int(y), str('-'))
    if yara_results:
        stdscr.addstr(18, 1, yara_results, curses.color_pair(1))
    else:
        stdscr.addstr(18, 1, 'None')

    i = 7
    if port_number:
        for number, description in zip(port_number[::2], port_number[1::2]):
            stdscr.addstr(i, int(y + 11), str(number), curses.color_pair(1))
            stdscr.addstr(i, int(y + 18), str(description), curses.color_pair(1))
            i += 1
    else:
        stdscr.addstr(7, 67, 'None')

    stdscr.addstr(0, 30, 'ThreatHound v.1.0', curses.A_BOLD)
    stdscr.addstr(2, 1, 'Local IP Address:  ')
    stdscr.addstr(3, 1, str(hunter.get_ip()), curses.color_pair(2))

    stdscr.addstr(22, 1, 'All detected events will be saved to "/var/log/threathound<today\'s date>" file.')
    stdscr.hline(23, 1, '_', int(y+25))
    stdscr.addstr(25, 1, 'Press (Ctrl+C) to exit')

    stdscr.refresh()
