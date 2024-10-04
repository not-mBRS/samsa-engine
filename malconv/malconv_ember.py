#!/usr/bin/python

def main(): 
    from keras.layers import Dense, Conv1D, Activation, GlobalMaxPooling1D, Input, Embedding, Multiply
    from keras.models import Model
    from keras import backend as K
    from keras import metrics
    from keras.preprocessing import sequence
    import matplotlib.pyplot as plt
    import os
    import random
    import argparse
    import numpy as np
    import requests

    batch_size = 100
    input_dim = 257  # every byte plus a special padding symbol
    padding_char = 256
    maxlen = 2**21  # 2MB
    embedding_size = 8

    parser = argparse.ArgumentParser()
    parser.add_argument('train_path', type=str, help="Path to training dataset")
    parser.add_argument('val_path', type=str, help="Path to validation dataset")
    parser.add_argument('--gpus', help='Number of GPUs', default=1)

    args = parser.parse_args()
    ngpus = int(args.gpus)

    # Define the model
    inp = Input(shape=(maxlen,))
    emb = Embedding(input_dim, embedding_size)(inp)
    filt = Conv1D(filters=128, kernel_size=500, strides=500, use_bias=True, activation='relu', padding='valid')(emb)
    attn = Conv1D(filters=128, kernel_size=500, strides=500, use_bias=True, activation='sigmoid', padding='valid')(emb)
    gated = Multiply()([filt, attn])
    feat = GlobalMaxPooling1D()(gated)
    dense = Dense(128, activation='relu')(feat)
    outp = Dense(1, activation='sigmoid')(dense)

    basemodel = Model(inp, outp)

    if os.path.exists('dmalconv.h5'):
        print("Restoring dmalconv.h5 from disk for continuation training...")
        basemodel.load_weights('dmalconv.h5')

    basemodel.summary()
    print(f"Using {ngpus} GPUs")

    # Multi-GPU support
    if ngpus > 1:
        from keras.utils import multi_gpu_model
        model = multi_gpu_model(basemodel, gpus=ngpus)
    else:
        model = basemodel

    from keras.optimizers import SGD
    model.compile(loss='binary_crossentropy',
              optimizer=SGD(learning_rate=0.01, momentum=0.9, nesterov=True),
              metrics=[metrics.binary_accuracy])

    # Function to convert the file bytes into numpy arrays
    def bytez_to_numpy(bytez, maxlen):
        b = np.ones((maxlen,), dtype=np.uint16) * padding_char
        bytez = np.frombuffer(bytez[:maxlen], dtype=np.uint8)
        b[:len(bytez)] = bytez
        return b

    # Generator for reading the data
    def generator(folder, batch_size, shuffle=True):
        X = []
        y = []
        files = []
        labels = []
        
        for root, dirs, file_names in os.walk(folder):
            for file in file_names:
                if file.endswith('.exe'):  # Process only executables
                    full_path = os.path.join(root, file)
                    label = 1 if 'malware' in root else 0
                    files.append(full_path)
                    labels.append(label)
        
        zipped = list(zip(files, labels))
        while True:
            if shuffle:
                random.shuffle(zipped)
            for file_path, label in zipped:
                with open(file_path, 'rb') as f:
                    bytez = f.read()
                    x = bytez_to_numpy(bytez, maxlen)
                    X.append(x)
                    y.append(label)
                if len(X) == batch_size:
                    yield np.asarray(X, dtype=np.uint16), np.asarray(y)
                    X = []
                    y = []

    # Create data generators
    train_gen = generator(args.train_path, batch_size)
    val_gen = generator(args.val_path, batch_size)

    from keras.callbacks import LearningRateScheduler, History

    base_lr = model.optimizer.learning_rate.numpy()
    
    def schedule(epoch):
        return base_lr / 10.0**(epoch//2)

    history = History()

    # Train the model
    history = model.fit(
        train_gen,
        steps_per_epoch=100,  
        epochs=10,
        validation_data=val_gen,
        validation_steps=50,  
        callbacks=[LearningRateScheduler(schedule), history]
    )

    # Save the model weights
    basemodel.save('dmalconv.h5')

    # Plot the training and validation accuracy/loss
    def plot_history(history):
        plt.figure(figsize=(12, 4))

        # Accuracy plot
        plt.subplot(1, 2, 1)
        plt.plot(history.history['binary_accuracy'], label='Train Accuracy')
        plt.plot(history.history['val_binary_accuracy'], label='Validation Accuracy')
        plt.title('Accuracy')
        plt.xlabel('Epochs')
        plt.ylabel('Accuracy')
        plt.legend()

        # Loss plot
        plt.subplot(1, 2, 2)
        plt.plot(history.history['loss'], label='Train Loss')
        plt.plot(history.history['val_loss'], label='Validation Loss')
        plt.title('Loss')
        plt.xlabel('Epochs')
        plt.ylabel('Loss')
        plt.legend()

        plt.show()

    # Call the plotting function to visualize the results
    plot_history(history)


if __name__ == '__main__':
    main()
