import os
from keras import Model, optimizers, preprocessing, applications, callbacks, layers
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, ConfusionMatrixDisplay
import pandas as pd
BATCH_SIZE = 16
EPOCHS = 20 
DIM = 299 
LEARNING_RATE = 0.001 
BETA_2 = 0.999 
MOMENT = 0.9 

## MODEL

n_classes=9
input_shape = (DIM, DIM, 3) 
optim = optimizers.Adam(learning_rate=LEARNING_RATE, beta_1=MOMENT, beta_2=BETA_2)

early_stop = callbacks.EarlyStopping(monitor="val_loss",
                           patience=7,
                           mode="min")
tl_checkpoint_1 = callbacks.ModelCheckpoint(filepath="./first_test.weights.keras",
                                  save_best_only=True,
                                  verbose=1)

def create_model(input_shape, n_classes, optimizer=optim):
    conv_base = applications.Xception(include_top=False,
                     weights='imagenet', 
                     input_shape=input_shape)
    top_model = conv_base.output
    top_model = layers.GlobalAveragePooling2D()(top_model)
    output_layer = layers.Dense(n_classes, activation='softmax')(top_model)


    model = Model(inputs=conv_base.input, outputs=output_layer)
    model.compile(optimizer=optimizer, 
                  loss='categorical_crossentropy',
                  metrics=['accuracy'])
    
    return model
modello = create_model(input_shape, n_classes, optim)
#modello.summary()

## DATASET

download_dir = Path('../Datasets/Images')
train_data_dir = download_dir/'Malware_train'
val_data_dir = download_dir/'Malware_val'
test_data_dir = download_dir/'Malware_test_addition_imgs'
#classes_names = sorted(os.listdir(download_dir/'train'))
'''
traingen = preprocessing.image_dataset_from_directory(train_data_dir, # (batch, samples, labels)
                                               image_size=(DIM, DIM),
                                               label_mode='categorical',
                                               batch_size=BATCH_SIZE, 
                                               shuffle=True)

validgen = preprocessing.image_dataset_from_directory(val_data_dir,
                                               image_size=(DIM, DIM),
                                               label_mode='categorical',
                                               shuffle=True)
'''
testgen = preprocessing.image_dataset_from_directory(test_data_dir,
                                             label_mode="categorical",
                                         color_mode="rgb",
                                         shuffle=False,
                                         image_size=(DIM,DIM),
                                         seed=27,
                                         batch_size=32,)
  
## TRAINING

'''
vgg_ft_history = modello.fit(traingen,
                                  batch_size=BATCH_SIZE,
                                  epochs=EPOCHS,
                                  validation_data=validgen,
                                  callbacks=[tl_checkpoint_1, early_stop],
                                  verbose=1)
'''
## EVALUATION
labels_list = []
for images, labels in testgen:
    labels_list.extend(labels.numpy())

y_test=np.argmax(np.array(labels_list), axis=1)
file_paths = testgen.file_paths

modello.load_weights('./first_test.weights.keras')

vgg_preds_ft = modello.predict(testgen)
confidence = np.max(vgg_preds_ft, axis=1)
vgg_pred_classes_ft = np.argmax(vgg_preds_ft, axis=1)
vgg_acc_ft = accuracy_score(y_test, vgg_pred_classes_ft)

print("Model Accuracy with Fine-Tuning: {:.2f}%".format(vgg_acc_ft * 100)) 
print(classification_report(y_test, vgg_pred_classes_ft, digits=3))

df = pd.DataFrame({'name': file_paths, 
                    'class_true': y_test, 
                    'class_pred': vgg_pred_classes_ft, 
                    'confidence': confidence
                    })
#df.to_csv('./clean.csv', index=False)


modello.load_weights('./first_test.weights.keras')
cmp=ConfusionMatrixDisplay(confusion_matrix(y_test, vgg_pred_classes_ft))
fig, ax = plt.subplots(figsize=(15,15))
cmp.plot(ax=ax)
plt.show()