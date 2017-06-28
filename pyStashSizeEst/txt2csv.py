import csv

csv_out = csv.writer(open('temp.csv', 'w',newline=''), delimiter=',')
csv_out.writerow(['e', 's6'])

f = open('temp.txt')
for line in f.readlines():
  vals = line.split()
  # DD, WVHT, MWD
  csv_out.writerow([vals[0], vals[3]])
f.close()