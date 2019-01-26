# -*- coding: utf-8 -*-
"""31bitperdiction.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/15z1ewVllZ2UAVJBYmrgDvWFLmeDykNqn
"""

#import the library pandas as pd
import pandas as pd
import numpy as np
from google.colab import files

upload=files.upload()

df=pd.read_csv('CompleteDataset (2).csv')
pd.read_csv('CompleteDataset (2).csv')

#create a dataframe with all training data except the target column
#and here 
X = df.iloc[:, 0:16].values
Y = df.iloc[:,46].values

from sklearn import datasets, linear_model


from sklearn.model_selection import train_test_split
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size = 0.1)

print(X)
print(Y)

X_train=X_train/15
X_test=X_test/15

import tensorflow as tf
from tensorflow.keras import layers
import tensorflow as tf
from tensorflow.keras import layers
from keras.models import Sequential
from keras.layers import Dropout
from keras.layers import Flatten
from keras.layers import LSTM
from keras.layers import Embedding
from keras.layers import Dense

topwords=32
# Build the model 

#model = Sequential()
#model.add(Embedding( topwords,1, input_length=13)) 
#model.add(LSTM(100))
#model.add(Dense(1, activation='sigmoid'))


#model.compile(loss='binary_crossentropy',optimizer='adam', metrics=['accuracy'])
model = Sequential()
#len of X_train here is the 8000.
#1 here is the column.
#13 is the feature.
X_train=X_train.reshape(len(X_train),1,16)
X_test=X_test.reshape(len(X_test),1,16)
model.add(LSTM(100, input_shape = (None,16),activation='relu')) 
model.add(Dense(output_dim=1, activation='sigmoid'))
print('Model loaded.')
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
print('Model compiled.')

print(model.summary())

model.fit(X_train,Y_train,epochs=20)

val_loss,val_acc=model.evaluate(X_test,Y_test)
print(val_loss,val_acc)

p=model.predict([X_test])
 
import numpy as np
for i in range(0,40):
   print(p[i],Y_test[i])

p = (p > 0.5)

from sklearn.metrics import confusion_matrix
cm = confusion_matrix(Y_test, p)
print(cm)

