#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <commctrl.h>
#else
#include <fcntl.h>
#include <gtk/gtk.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static int key_is_valid(const char *key) {
    size_t key_len = strlen(key);
    return key_len > 0 && key_len <= 128;
}

static int gui_experimental_enabled(void) {
    const char *v = getenv("NEXUS_ARX_GUI_EXPERIMENTAL");
    if (v == NULL) return 0;
    return strcmp(v, "1") == 0 || strcmp(v, "true") == 0 || strcmp(v, "TRUE") == 0;
}

/*
 * Nexus-ARX-T backend invocation.
 * The backend now takes:
 *   nexus_arx_t <E|D> <input> <output> [--pass-stdin] [--experimental]
 * Password is supplied securely via env/stdin instead of argv.
 */
#ifdef _WIN32
static int process_file(int mode_decrypt, const char *infile, const char *outfile, const char *key) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD exit_code = 0;
    char command_line[2048];
    int ok = 0;
    int use_experimental = gui_experimental_enabled();

    if (!key_is_valid(key)) return 0;

    if (use_experimental && !mode_decrypt) {
        snprintf(command_line, sizeof(command_line),
                 ".\\nexus_arx_t.exe %c \"%s\" \"%s\" --experimental",
                 mode_decrypt ? 'D' : 'E', infile, outfile);
    } else {
        snprintf(command_line, sizeof(command_line),
                 ".\\nexus_arx_t.exe %c \"%s\" \"%s\"",
                 mode_decrypt ? 'D' : 'E', infile, outfile);
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    if (!SetEnvironmentVariableA("NEXUS_ARX_PASSWORD", key)) {
        return 0;
    }

    if (!CreateProcessA(NULL, command_line, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        SetEnvironmentVariableA("NEXUS_ARX_PASSWORD", NULL);
        return 0;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    ok = (exit_code == 0);
    SetEnvironmentVariableA("NEXUS_ARX_PASSWORD", NULL);
    return ok;
}
#else
static int process_file(int mode_decrypt, const char *infile, const char *outfile, const char *key) {
    pid_t child_pid;
    int status = 0;
    int pw_pipe[2];
    int use_experimental = gui_experimental_enabled();

    if (!key_is_valid(key)) return 0;

    if (pipe(pw_pipe) != 0) return 0;

    child_pid = fork();
    if (child_pid < 0) {
        close(pw_pipe[0]);
        close(pw_pipe[1]);
        return 0;
    }

    if (child_pid == 0) {
        int devnull_fd;
        close(pw_pipe[1]);
        if (dup2(pw_pipe[0], STDIN_FILENO) < 0) {
            _exit(127);
        }
        close(pw_pipe[0]);

        devnull_fd = open("/dev/null", O_WRONLY);
        if (devnull_fd >= 0) {
            dup2(devnull_fd, STDOUT_FILENO);
            dup2(devnull_fd, STDERR_FILENO);
            close(devnull_fd);
        }

        if (use_experimental && !mode_decrypt) {
            execl("./nexus_arx_t", "./nexus_arx_t",
                  mode_decrypt ? "D" : "E",
                  infile, outfile, "--pass-stdin", "--experimental", (char *) NULL);
        } else {
            execl("./nexus_arx_t", "./nexus_arx_t",
                  mode_decrypt ? "D" : "E",
                  infile, outfile, "--pass-stdin", (char *) NULL);
        }
        _exit(127);
    }

    close(pw_pipe[0]);
    {
        size_t key_len = strlen(key);
        ssize_t w1 = write(pw_pipe[1], key, key_len);
        ssize_t w2 = write(pw_pipe[1], "\n", 1);
        (void)w1;
        (void)w2;
    }
    close(pw_pipe[1]);

    waitpid(child_pid, &status, 0);

    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

#ifdef _WIN32

// ==========================================
// Windows Win32 API GUI Implementation
// ==========================================
HWND hInfile, hOutfile, hKey;

void OnBrowse(HWND hwnd, HWND hEdit) {
    OPENFILENAME ofn;
    char szFile[260] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All Files\0*.*\0Text Files\0*.TXT\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn) == TRUE) {
        SetWindowText(hEdit, szFile);
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            CreateWindow("BUTTON", "Encrypt", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON, 20, 20, 80, 20, hwnd, (HMENU)101, NULL, NULL);
            CreateWindow("BUTTON", "Decrypt", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON, 110, 20, 80, 20, hwnd, (HMENU)102, NULL, NULL);
            SendDlgItemMessage(hwnd, 101, BM_SETCHECK, BST_CHECKED, 0); // Default Encrypt

            CreateWindow("STATIC", "Input File:", WS_VISIBLE | WS_CHILD, 20, 60, 80, 20, hwnd, NULL, NULL, NULL);
            hInfile = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 110, 60, 200, 20, hwnd, NULL, NULL, NULL);
            CreateWindow("BUTTON", "Browse...", WS_VISIBLE | WS_CHILD, 320, 60, 80, 20, hwnd, (HMENU)103, NULL, NULL);

            CreateWindow("STATIC", "Output File:", WS_VISIBLE | WS_CHILD, 20, 100, 80, 20, hwnd, NULL, NULL, NULL);
            hOutfile = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 110, 100, 200, 20, hwnd, NULL, NULL, NULL);
            CreateWindow("BUTTON", "Browse...", WS_VISIBLE | WS_CHILD, 320, 100, 80, 20, hwnd, (HMENU)104, NULL, NULL);

            CreateWindow("STATIC", "Password:", WS_VISIBLE | WS_CHILD, 20, 140, 110, 20, hwnd, NULL, NULL, NULL);
            hKey = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD, 140, 140, 180, 20, hwnd, NULL, NULL, NULL);

            CreateWindow("BUTTON", "Process", WS_VISIBLE | WS_CHILD, 20, 180, 380, 30, hwnd, (HMENU)105, NULL, NULL);
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == 103) OnBrowse(hwnd, hInfile);
            if (LOWORD(wParam) == 104) OnBrowse(hwnd, hOutfile); // Actually openfile for output can use GetSaveFileName but simplifying
            if (LOWORD(wParam) == 105) {
                char infile[260], outfile[260], key_str[130];
                GetWindowText(hInfile, infile, 260);
                GetWindowText(hOutfile, outfile, 260);
                GetWindowText(hKey, key_str, 129);

                if (strlen(infile) == 0 || strlen(outfile) == 0 || strlen(key_str) == 0) {
                    MessageBox(hwnd, "All fields are required.", "Error", MB_OK | MB_ICONERROR);
                    return 0;
                }

                int mode_decrypt = (SendDlgItemMessage(hwnd, 102, BM_GETCHECK, 0, 0) == BST_CHECKED);

                if (!key_is_valid(key_str)) {
                    MessageBox(hwnd, "Password must be between 1 and 128 characters.", "Error", MB_OK | MB_ICONERROR);
                    return 0;
                }

                if (process_file(mode_decrypt, infile, outfile, key_str)) {
                    MessageBox(hwnd, "Operation successful!", "Success", MB_OK | MB_ICONINFORMATION);
                } else {
                    MessageBox(hwnd, "Operation failed! Check files.", "Error", MB_OK | MB_ICONERROR);
                }
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char CLASS_NAME[] = "NexusARXEncryptorClass";

    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, "Nexus-ARX-T File Encryptor", WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 450, 280,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}

#else

// ==========================================
// Linux GTK3 API GUI Implementation
// ==========================================
static GtkWidget *window, *entry_in, *entry_out, *entry_key, *radio_enc, *radio_dec;

static void on_process_clicked(GtkWidget *widget, gpointer data) {
    const char *infile = gtk_entry_get_text(GTK_ENTRY(entry_in));
    const char *outfile = gtk_entry_get_text(GTK_ENTRY(entry_out));
    const char *key_str = gtk_entry_get_text(GTK_ENTRY(entry_key));
    
    int mode_decrypt = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(radio_dec));
    
    if (strlen(infile) == 0 || strlen(outfile) == 0 || strlen(key_str) == 0) {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "All fields are required.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }
    
    if (!key_is_valid(key_str)) {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Password must be between 1 and 128 characters.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }
    
    if (process_file(mode_decrypt, infile, outfile, key_str)) {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_INFO, GTK_BUTTONS_CLOSE, "Operation successful!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
    } else {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Operation failed! Check file permissions or paths.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
    }
}

static void on_browse_in(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Open Input File", GTK_WINDOW(window), GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel", GTK_RESPONSE_CANCEL, "_Open", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        gtk_entry_set_text(GTK_ENTRY(entry_in), filename);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void on_browse_out(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Save Output File", GTK_WINDOW(window), GTK_FILE_CHOOSER_ACTION_SAVE, "_Cancel", GTK_RESPONSE_CANCEL, "_Save", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        gtk_entry_set_text(GTK_ENTRY(entry_out), filename);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Nexus-ARX-T File Encryptor");
    gtk_window_set_default_size(GTK_WINDOW(window), 450, 250);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_add(GTK_CONTAINER(window), grid);

    // Mode
    GtkWidget *label_mode = gtk_label_new("Mode:");
    radio_enc = gtk_radio_button_new_with_label(NULL, "Encrypt");
    radio_dec = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(radio_enc), "Decrypt");
    
    GtkWidget *mode_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(mode_box), radio_enc, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mode_box), radio_dec, FALSE, FALSE, 0);

    gtk_grid_attach(GTK_GRID(grid), label_mode, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), mode_box, 1, 0, 2, 1);

    // Input File
    GtkWidget *label_in = gtk_label_new("Input File:");
    entry_in = gtk_entry_new();
    gtk_widget_set_hexpand(entry_in, TRUE);
    GtkWidget *btn_in = gtk_button_new_with_label("Browse...");
    g_signal_connect(btn_in, "clicked", G_CALLBACK(on_browse_in), NULL);

    gtk_grid_attach(GTK_GRID(grid), label_in, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), entry_in, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_in, 2, 1, 1, 1);

    // Output File
    GtkWidget *label_out = gtk_label_new("Output File:");
    entry_out = gtk_entry_new();
    GtkWidget *btn_out = gtk_button_new_with_label("Browse...");
    g_signal_connect(btn_out, "clicked", G_CALLBACK(on_browse_out), NULL);

    gtk_grid_attach(GTK_GRID(grid), label_out, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), entry_out, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_out, 2, 2, 1, 1);

    // Key
    GtkWidget *label_key = gtk_label_new("Password:");
    entry_key = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry_key), FALSE);
    
    gtk_grid_attach(GTK_GRID(grid), label_key, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), entry_key, 1, 3, 2, 1);

    // Process Button
    GtkWidget *btn_process = gtk_button_new_with_label("Start Process");
    g_signal_connect(btn_process, "clicked", G_CALLBACK(on_process_clicked), NULL);
    gtk_grid_attach(GTK_GRID(grid), btn_process, 0, 4, 3, 1);

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}

#endif
