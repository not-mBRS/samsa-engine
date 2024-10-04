import os
from keras import Model, optimizers, preprocessing, applications, callbacks, layers
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, ConfusionMatrixDisplay
import time
import datetime
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
tl_checkpoint_1 = callbacks.ModelCheckpoint(filepath="./Weights/first_test.weights.keras",
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

download_dir = Path('./dataset/')
train_data_dir = download_dir/'Malware_train'
val_data_dir = download_dir/'Malware_val'
test_data_dir = download_dir/'Malware_test'
#classes_names = sorted(os.listdir(download_dir/'train'))

traingen = preprocessing.image_dataset_from_directory(train_data_dir, # (batch, samples, labels)
                                               image_size=(DIM, DIM),
                                               label_mode='categorical',
                                               batch_size=BATCH_SIZE, 
                                               shuffle=True)

validgen = preprocessing.image_dataset_from_directory(val_data_dir,
                                               image_size=(DIM, DIM),
                                               label_mode='categorical',
                                               shuffle=True)

testgen = preprocessing.image_dataset_from_directory(test_data_dir,
                                             image_size=(DIM, DIM),
                                             label_mode=None,
                                             batch_size=1,
                                             shuffle=False)
  
## TRAINING

start_training_time = time.time()

vgg_ft_history = modello.fit(traingen,
                                  batch_size=BATCH_SIZE,
                                  epochs=EPOCHS,
                                  validation_data=validgen,
                                  callbacks=[tl_checkpoint_1, early_stop],
                                  verbose=1)

## EVALUATION
y_test=1 #fix
end_training_time = time.time()
modello.load_weights('./Weights/first_test.weights.h5')

start_prediction_time = time.time()
vgg_preds_ft = modello.predict(testgen)
end_prediction_time = time.time()
vgg_pred_classes_ft = np.argmax(vgg_preds_ft, axis=1)
vgg_acc_ft = accuracy_score(y_test, vgg_pred_classes_ft)

print("VGG16 Model Accuracy with Fine-Tuning: {:.2f}%".format(vgg_acc_ft * 100)) 
print("Training time: ", str(datetime.timedelta(seconds=end_training_time-start_training_time)))
print("Prediction time: ", str(datetime.timedelta(seconds=end_prediction_time-start_prediction_time)))
print(classification_report(y_test, vgg_pred_classes_ft, digits=3))

modello.load_weights('./Weights/first_test.weights.h5')
cmp=ConfusionMatrixDisplay(confusion_matrix(y_test, vgg_pred_classes_ft))
fig, ax = plt.subplots(figsize=(15,15))
cmp.plot(ax=ax)
plt.show()