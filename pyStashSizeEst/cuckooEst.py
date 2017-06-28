import numpy as np
from sklearn import datasets, linear_model
import matplotlib.pyplot as plt
import pandas as pd

data = pd.read_csv('stashSize_2h.csv', index_col=False, header=0)
x = data.e.values
y6 = data.nn6.values
y8 = data.nn8.values
y10 = data.nn10.values
y12 = data.nn12.values
y14 = data.nn14.values
y16 = data.nn16.values
y18 = data.nn18.values
#print (x) # prints: [ 0.  1.  2.  3.  4.  5.  6.  7.  8.  9.]

x = x.reshape(len(x), 1)
y6 = y6.reshape(len(y6), 1)
y8 = y8.reshape(len(y8), 1)
y10 = y10.reshape(len(y10), 1)
y12 = y12.reshape(len(y12), 1)
y14 = y14.reshape(len(y14), 1)
y16 = y16.reshape(len(y16), 1)
y18 = y18.reshape(len(y18), 1)
regr = linear_model.LinearRegression()

x=x[:len(y6)]
x2=np.arange(x[len(x)-1],10,0.1)
x2 = x2.reshape(len(x2), 1)
regr.fit(x, y6)
plt.scatter(x, y6,  color='gray',s=1)
plt.plot(x, regr.predict(x), color='gray', linewidth=0.5,label='6')
#plt.plot(x2, regr.predict(x2), linestyle='--', color='gray', linewidth=0.5)
plt.plot(x2, regr.predict(x2), color='gray', linewidth=0.5)

leny=np.count_nonzero(~np.isnan(y8))
x=x[:leny]
y8=y8[:leny]
x2=np.arange(x[len(x)-1],10,0.1)
x2 = x2.reshape(len(x2), 1)
regr.fit(x, y8)
plt.scatter(x, y8,  color='pink',s=1)
plt.plot(x, y8, color='pink', linewidth=0.5,label='8')
plt.plot(x2, regr.predict(x2),  color='pink', linewidth=0.5)

leny=np.count_nonzero(~np.isnan(y10))
x=x[:leny]
y10=y10[:leny]
x2=np.arange(x[len(x)-1],10,0.1)
x2 = x2.reshape(len(x2), 1)
regr.fit(x, y10)
plt.scatter(x, y10,  color='green',s=1)
plt.plot(x, regr.predict(x), color='green', linewidth=0.5,label='10')
plt.plot(x2, regr.predict(x2), color='green', linewidth=0.5)

leny=np.count_nonzero(~np.isnan(y12))
x=x[:leny]
y12=y12[:leny]
x2=np.arange(x[len(x)-1],10,0.1)
x2 = x2.reshape(len(x2), 1)
regr.fit(x, y12)
plt.scatter(x, y12,  color='blue',s=1)
plt.plot(x, regr.predict(x), color='blue', linewidth=0.5,label='12')
plt.plot(x2, regr.predict(x2), color='blue', linewidth=0.5)

leny=np.count_nonzero(~np.isnan(y14))
x=x[:leny]
y14=y14[:leny]
x2=np.arange(x[len(x)-1],10,0.1)
x2 = x2.reshape(len(x2), 1)
regr.fit(x, y14)
plt.scatter(x, y14,  color='red',s=1)
plt.plot(x, regr.predict(x), color='red', linewidth=0.5,label='14')
plt.plot(x2, regr.predict(x2),  color='red', linewidth=0.5)

leny=np.count_nonzero(~np.isnan(y16))
x=x[:leny]
y16=y16[:leny]
x2=np.arange(x[len(x)-1],10,0.1)
x2 = x2.reshape(len(x2), 1)
regr.fit(x, y16)
plt.scatter(x, y16,  color='purple',s=1)
plt.plot(x, regr.predict(x), color='purple', linewidth=0.5,label='16')
plt.plot(x2, regr.predict(x2),  color='purple', linewidth=0.5)

leny=np.count_nonzero(~np.isnan(y18))
x=x[:leny]
y18=y18[:leny]
x2=np.arange(x[len(x)-1],10,0.1)
x2 = x2.reshape(len(x2), 1)
regr.fit(x, y18)
plt.scatter(x, y18,  color='orange',s=1)
plt.plot(x, regr.predict(x), color='orange', linewidth=0.5,label='18')
plt.plot(x2, regr.predict(x2),  color='orange', linewidth=0.5)

#plt.xticks(())
#plt.yticks(())
plt.ylabel('lambda')
plt.xlabel('e')
plt.legend()
plt.show()
