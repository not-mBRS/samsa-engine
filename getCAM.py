import keras as ks
import numpy as np
import tensorflow as tf
import pandas as pd
import os

last_conv_layer_name = "last_pool"

def get_img_array(img_path, size):
    img = ks.preprocessing.image.load_img(img_path, target_size=size)
    array = ks.preprocessing.image.img_to_array(img)
    array = np.expand_dims(array, axis=0)
    return array

def get_heatmap_hirescam(img_array, model, layerName, classIdx=None): 
    gradModel = Model(
        inputs=[model.input],
        outputs=[model.get_layer(layerName).output, model_cnn.output])
    with tf.GradientTape() as tape:
        convOutputs, predictions = gradModel(img_array)
        classIdx = tf.argmax(predictions[0])
        loss = predictions[:, classIdx]
    grads = tape.gradient(loss, convOutputs)
    convOutputs = convOutputs[0]
    heatmap = convOutputs * grads
    heatmap = np.sum(heatmap, axis=-1)
    heatmap = tf.squeeze(heatmap)
    heatmap = tf.maximum(heatmap, 0) / tf.math.reduce_max(heatmap)
    return heatmap.numpy()

model_cnn.load_weights('.\\Weights\\checkpoint'+perc)

model_cnn.layers[-1].activation = None

for dataset_path in dataset_paths:
    df_heatmaps=pd.DataFrame(columns=np.arange(1157))
    for i in os.listdir(dataset_path):
        counter=0
        print(i)
        for j in os.listdir(dataset_path+"\\"+i):
            if counter%100==0:
                    print(counter)
            counter+=1
            img_path = dataset_path+"\\"+i+"\\"+j
            img_array = get_img_array(img_path, size=(DIM,DIM))
            heatmap = get_heatmap_hirescam(img_array, model_cnn, last_conv_layer_name)
            df_heatmaps=pd.concat([df_heatmaps,pd.Series([j]+heatmap.flatten().tolist(), index=df_heatmaps.columns).to_frame().T], ignore_index=True)

    df_heatmaps.to_csv('.\\Results\\Masks\\masks.morph1.hirescam'+perc+'.csv', index=False)
    break
