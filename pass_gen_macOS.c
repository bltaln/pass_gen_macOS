#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define SALT_SIZE 16
#define ITERATIONS 10000
#define KEY_LENGTH 32

GtkWidget *passwordEntry;
GtkWidget *generateButton;
GtkWidget *copyButton;
GtkWidget *generatedLabel;

void generate_password(GtkWidget *widget, gpointer data) {
    const gchar *password = gtk_entry_get_text(GTK_ENTRY(passwordEntry));

    // Generate random salt
    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        g_print("Failed to generate random salt\n");
        return;
    }

    // Generate derived key using PBKDF2
    unsigned char derivedKey[KEY_LENGTH];
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, ITERATIONS, EVP_sha256(), KEY_LENGTH, derivedKey) != 1) {
        g_print("Failed to generate derived key\n");
        return;
    }

    // Convert derived key to base64
    BIO *base64Bio = BIO_new(BIO_f_base64());
    BIO *memBio = BIO_new(BIO_s_mem());
    BIO_push(base64Bio, memBio);
    BIO_write(base64Bio, derivedKey, KEY_LENGTH);
    BIO_flush(base64Bio);
    BUF_MEM *memBuf;
    BIO_get_mem_ptr(base64Bio, &memBuf);
    char *base64Key = (char *)malloc(memBuf->length);
    memcpy(base64Key, memBuf->data, memBuf->length - 1);
    base64Key[memBuf->length - 1] = '\0';

    // Display the generated password in the GtkLabel
    gtk_label_set_text(GTK_LABEL(generatedLabel), base64Key);

    // Enable copy button
    gtk_widget_set_sensitive(copyButton, TRUE);

    // Cleanup
    free(base64Key);
    BIO_free_all(base64Bio);
}

void copy_password(GtkWidget *widget, gpointer data) {
    const gchar *password = gtk_label_get_text(GTK_LABEL(generatedLabel));

    // Copy password to clipboard
    GtkClipboard *clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(clipboard, password, -1);
}

void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window;
    GtkWidget *grid;

    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Password Generator for macOS Developed by www.linecode.ro");
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    gtk_window_set_default_size(GTK_WINDOW(window), 300, 200);

    grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_add(GTK_CONTAINER(window), grid);

    // Password entry
    passwordEntry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(passwordEntry), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(passwordEntry), "Enter master password");
    gtk_grid_attach(GTK_GRID(grid), passwordEntry, 0, 0, 1, 1);

    // Generate button
    generateButton = gtk_button_new_with_label("Generate Password");
    g_signal_connect(generateButton, "clicked", G_CALLBACK(generate_password), NULL);
    gtk_grid_attach(GTK_GRID(grid), generateButton, 0, 1, 1, 1);

    // Generated password label
    generatedLabel = gtk_label_new(NULL);
    gtk_label_set_line_wrap(GTK_LABEL(generatedLabel), TRUE);
    gtk_grid_attach(GTK_GRID(grid), generatedLabel, 0, 2, 1, 1);

    // Copy button
    copyButton = gtk_button_new_with_label("Copy Password");
    g_signal_connect(copyButton, "clicked", G_CALLBACK(copy_password), NULL);
    gtk_grid_attach(GTK_GRID(grid), copyButton, 0, 3, 1, 1);
    gtk_widget_set_sensitive(copyButton, FALSE);

    gtk_widget_show_all(window);
}

int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

    app = gtk_application_new("com.example.passgenmacos", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}

