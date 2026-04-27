import re
from collections import defaultdict
from datetime import datetime, timedelta

log_file = "auth.log"
report_file = "report.txt"

FAILED_THRESHOLD = 5
TIME_WINDOW_MINUTES = 2

failed_attempts = defaultdict(int)
targeted_users = defaultdict(int)
timeline = []
ip_events = defaultdict(list)

def parse_timestamp(line):
    timestamp_text = line[:15]
    return datetime.strptime(timestamp_text, "%b %d %H:%M:%S")

# Helper to print + write
def write_line(f, text=""):
    print(text)
    f.write(text + "\n")

with open(log_file, "r") as file:
    for line in file:
        if "authentication failure" in line:
            timestamp = parse_timestamp(line)

            host_match = re.search(r"rhost=([^\s]+)", line)
            user_match = re.search(r"user=([^\s]+)", line)

            if host_match:
                host = host_match.group(1)
                failed_attempts[host] += 1
                ip_events[host].append(timestamp)

                timeline.append({
                    "time": timestamp,
                    "source": host,
                    "event": "authentication failure"
                })

            if user_match:
                user = user_match.group(1)
                targeted_users[user] += 1

# Write report
with open(report_file, "w") as report:

    write_line(report, "\n=== Security Incident Investigation Report ===\n")

    write_line(report, "Top Suspicious Sources:")
    for host, count in sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)[:5]:
        write_line(report, f"{host}: {count} failed attempts")

    write_line(report, "\nTargeted User Accounts:")
    for user, count in sorted(targeted_users.items(), key=lambda x: x[1], reverse=True)[:5]:
        write_line(report, f"{user}: {count} attempts")

    write_line(report, "\nTimeline of First 10 Suspicious Events:")
    for event in timeline[:10]:
        write_line(report, f"{event['time'].strftime('%b %d %H:%M:%S')} | {event['source']} | {event['event']}")

    write_line(report, "\nBrute Force Detection:")
    for host, times in ip_events.items():
        times.sort()

        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(minutes=TIME_WINDOW_MINUTES)

            attempts_in_window = [
                t for t in times
                if window_start <= t <= window_end
            ]

            if len(attempts_in_window) >= FAILED_THRESHOLD:
                write_line(
                    report,
                    f"ALERT: {host} made {len(attempts_in_window)} failed attempts within {TIME_WINDOW_MINUTES} minutes"
                )
                break

    write_line(report, "\nConclusion:")
    write_line(report, "Repeated authentication failures within a short time window indicate possible brute force activity.")

print(f"\nReport saved to {report_file}")