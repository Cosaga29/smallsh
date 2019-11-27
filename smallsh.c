/*
Author: Martin Edmunds
Date: 11/11/19
Description: A small, lightweight shell application that creates and manages child processes,
handles user input, and manages signal handler events sent from the OS.

Requires POSIX SOURCE >= 200809L for proper
signal handler defines and siginfo structures.
*/

#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <alloca.h>

#define MAX_LENGTH 2048
#define ARG_SIZE 256
#define MAX_ARGS 512
#define COMMENT_CODE #
#define MAX_BACKGROUND 100
#define DONE -5

//flag thats modified by signal handling functions: lets program know if a foreground process is running
int foreground_status;
//process status of a background talks
int process_status;
//flag thats modified by signal handling functions to signify if a process has ended
char process_ended;
//stores the most recent background process pid
int process_pid;
//flag to change terminal mode and logic
char foreground_only_mode;
//flag to let the program know
int foreground_flag;
//current foreground running processes pid
pid_t foreground_child;
//flag in order to check if a process has ended after the user is performing another task
int print_delayed_message;


/*
Struct used to pass into fork: Contains all relevant information about the state of the shell:
    arguments = current arguments that the user has entered on the command line
    arg_count = number of arguments the user has entered on the command line
    background = flag to determine if the process needs to be ran with backgrounding (& entered)
    background_processes = pointer to all currently running background_processes
    current_backgrounds = number of currently running background processes
*/
struct shellState
{
    char** arguments;
    int arg_count;
    char background;
    pid_t* background_processes;
    int* current_backgrounds;
};


void createFork(struct shellState s);
void processArguments(char* command_line, char** argument_pointers, int* arguments);
void catchSIGCHILD(int signo, siginfo_t* child_info, void(*to_call));
void catchSIGINT(int signo);
void catchSIGTSTP(int signo);
void exitShell(pid_t* background_processes, int exit_code);



int main(){

    //collection of background PIDs to manage by the shell
    pid_t background_processes[MAX_BACKGROUND];
    for(int i = 0; i < MAX_BACKGROUND; i++)
    {
        background_processes[i] = DONE;
    }

    process_ended = 0;
    char* command_line = NULL;
    size_t command_line_size = 0;
    char background;
    char stdin_override;
    foreground_flag = 0;
    foreground_only_mode = 0;
    print_delayed_message = 0;
    foreground_child = DONE;


    //number of currently running background processes
    int current_backgrounds = 0;

    //create array of strings each with ARG_SIZE char limit. Max 512 arguments.
    char** argument_pointers = (char**)malloc(sizeof(char*) * MAX_ARGS);
    for(int i = 0; i < MAX_ARGS;i++)
    {
        argument_pointers[i] = (char*)malloc(sizeof(char) * ARG_SIZE);
    }





    //define sigaction structures for storing handler functions
    struct sigaction SIGCHILD_action = {0}; struct sigaction USER2_action = {0}; struct sigaction ignore_action = {0};
    struct sigaction SIGINT_action = {0}; struct sigaction SIGTSTP_action = {0};

    /*
    register signal handler structs to signal handler functions
    Will be overrideing the sigchild, sigint and sigtstp functions
    */
    SIGCHILD_action.sa_sigaction = catchSIGCHILD;
    SIGINT_action.sa_handler = catchSIGINT;
    SIGTSTP_action.sa_handler = catchSIGTSTP;


    //block all other signals while handing these signals
    sigfillset(&SIGCHILD_action.sa_mask);
    sigfillset(&SIGINT_action.sa_mask);
    sigfillset(&SIGTSTP_action.sa_mask);


    //Setting action flags to SA_RESTART to re-prompt for getline and other non-reentrant functions
    SIGCHILD_action.sa_flags = SA_RESTART;
    SIGINT_action.sa_flags = SA_RESTART;
    SIGTSTP_action.sa_flags = SA_RESTART;
    ignore_action.sa_handler = SIG_IGN;

    //bind sigaction functions to the recieving signal from the OS
    sigaction(SIGCHLD, &SIGCHILD_action, NULL);
    sigaction(SIGHUP, &ignore_action, NULL);
    sigaction(SIGQUIT, &ignore_action, NULL);
    sigaction(SIGINT, &SIGINT_action, NULL);
    sigaction(SIGTSTP, &SIGTSTP_action, NULL);




    //while the user hasn't issued an exit command...
    while(1){ 

        //args to pass to fork = 0
        int arguments = 0;
        //clear backgrounding flag (if we're here, the main process has waited for the child to exit)
        background = 0;

        //check if any background processes have ended:
        int background_pid = waitpid(-1, &process_status, WNOHANG);
        //process all background wait events
        while(background_pid != -1 && background_pid != 0)
        {
            //find background_pid in current background processes:
            for(int i = 0; i < MAX_BACKGROUND; i++)
            {
                //set background process to DONE code
                if(background_processes[i] == background_pid)
                {
                    background_processes[i] = DONE;
                    current_backgrounds--;
                    break;
                }
            }

            //process status of waited background process:
            if(WIFSIGNALED(process_status) != 0)
            {
                printf("background pid %i is done: terminated by signal %i\n", background_pid, WTERMSIG(process_status));
                fflush(stdout);
            }
            else
            {
                printf("background pid %i is done: exit value %i\n", background_pid, WEXITSTATUS(process_status));
                fflush(stdout);
            }

            //check to see if any more backgrounds have finished
            background_pid = waitpid(-1, &process_status, WNOHANG);
        }
        



        //print prompt
        printf(": ");
        fflush(stdout);


        
        //get user input, place into 2048 char buffer on stack
        int bytesRead;
        //until getline has succeeded
        while(1)
        {
            bytesRead = getline(&command_line, &command_line_size, stdin);
            if(bytesRead == -1)
            {
                //getline() was interupted by signal; clear and attempt to re-read
                clearerr(stdin);
                bytesRead = getline(&command_line, &command_line_size, stdin);
            }
            else
            {
                break;
            }
        }


        //check that buffer wasn't overflowed
        if(bytesRead > MAX_LENGTH)
        {
            printf("Error, command line overflow!\n");
            fflush(stdout);
            exit(1);
        }

        //check if user entered a comment or a empty string
        if(command_line[0] == '#' || strlen(command_line) == 1){
            fflush(stdout);
            continue;
        }



        //process user arguments
        else{
            //remove newline char from terminal
            command_line[bytesRead - 1] = '\0';

            //if the user wants to background the process, set flag (looks for: |&|\n\0)
            if(command_line[bytesRead - 2] == '&')
            {
                //set the bbackground flag, used by fork to create a background process
                background = 1;

                //if we're in foreground only mode, do not allow backgrounding at all
                if(foreground_only_mode)
                {
                    //clear background flag
                    background = 0;
                    //remove & from argument list
                    command_line[bytesRead - 2] = '\0';
                }
            }

            processArguments(command_line, argument_pointers, &arguments);

        }











        //check for exit command; process inputted command:
        if(strstr(argument_pointers[0], "exit")){

            //free memory allocated for command array
            for(int i = 0; i < MAX_ARGS;i++)
            {
                free(argument_pointers[i]);
            }
            free(argument_pointers);

            //kill background processes started by this shell
            exitShell(background_processes, 0);

            //printf("Exiting shell...\n");
            //fflush(stdout);
            exit(0);
        }
        //check for CD command; process CD command TODO
        else if(strstr(argument_pointers[0], "cd"))
        {
            if(arguments == 1)
            {
                //cd by itself: change to home directory (~)
                //printf("%s\n", getenv("HOME"));
                chdir(getenv("HOME"));
            }
            else if(!chdir(argument_pointers[1]) == 0)
            {
                printf("no such directory\n");
            }
        }
        //check for status command; process status command
        else if(strstr(argument_pointers[0], "status"))
        {
            //process status of waited background process:
            if(WIFSIGNALED(foreground_status) != 0)
            {
                printf("terminated by signal %i\n", WTERMSIG(foreground_status));
                fflush(stdout);
            }
            else
            {
                printf("exit value %i\n", WEXITSTATUS(foreground_status));
                fflush(stdout);
            }
        }
        //else the user has given a command that shell does not support, check for BIN
        else
        {
            //fork off child for exec
            struct shellState state =
            {
                argument_pointers,
                arguments,
                background,
                &background_processes[0],
                &current_backgrounds,
            };


            createFork(state);

        }

    }
}







/*
Function that handles control of non-build in commands.
Processes generated here will either be in foreground or background mode.

The function does the following:
    -creates a local stack allocated copy of the arguments passed from main.
    The reason that I chose to use stack allocation is because this string array will be heavily modified
    and the last entry will simply be set to null. Allocating this on the stack ensures that I don't have to manage this memory :)

    -forks off a child which does the following:
        sets file descriptors before calling exec (exec'd process will inherit these)
        checks to see if user has overridden stdin
        checks to see if user has overridden stdout
        counts valid arguments copied into the stack allocated array
        checks for backgrounding command
        execs the command and arguments in the stack allocated array.

NOTE: Since the child recieves a copy of the parent's heap, there is still allocated memory on the heap from main.
However, when the child call's exec this memory should be cleaned up by the OS when the process changes.


The parent does the following:
    If the process was a foreground task, the parent waits for the child to complete execution.
    During this time, if the user elects to change the mode of the terminal, the message is printed afterwards.

    If the process was a background task,
    the parent adds the child to a collection of monitored processes
    if the number of processes exeedes the maximum, the all processes are terminated


*/
void createFork(struct shellState state)
{

    pid_t childPID = DONE;

    //create stack allocated command array that will be fed directly into the program to exec 
    char** localArgs = (char**)alloca(sizeof(char*) * state.arg_count + 1);
    //generate arg array for execv:
    int i;
    for(i = 0; i < state.arg_count; i++)
    {
        localArgs[i] = (char*)alloca(sizeof(char) * ARG_SIZE);
        strcpy(localArgs[i], state.arguments[i]);
        //printf("%s\n", localArgs[i]);
        fflush(stdout);
    }

    //spawn child
    childPID = fork();
    if(childPID == -1){ perror("Fork error\n"); exit(1);}


    //child code:
    if(childPID == 0)
    {
        //flag to set if the user has overridden stdin with <
        int stdin_override = 0;

        //child process sets file descriptors to overrides before calling exec
        int passed_args = 0;
        for(int i = 0; i < state.arg_count; i++)
        {
            //check for stdin override
            if(strstr(localArgs[i], "<"))
            {
                //override stdin
                int file_desc = open(localArgs[i + 1], O_RDONLY);
                if(file_desc == -1){perror("cant open()"); process_status = 1; exit(1);}

                //set stdin to whatever arg came after '<'
                dup2(file_desc, 0);

                //set override flag, so that stdin shouldn't go to dev/null
                stdin_override = 1;
                
                //don't count "<" or the file arg after as args to pass into exec
                passed_args--;
            }
            //check for stdout override
            else if(strstr(localArgs[i], ">"))
            {
                //override stdout
                int file_desc = open(localArgs[i + 1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if(file_desc == -1){perror("cant open()"); process_status = 1; exit(1);}

                //set stdout to whatever arg came after '<'
                dup2(file_desc, 1);

                //don't count ">" or the file arg after as args to pass into exec
                passed_args--;
            } 
            else
            {
                //argument needed for exec'd function, count it
                passed_args++;
            }
        }

        //if this is a backgrounded process AND stdin hasn't been overridden:
        if(state.background && !stdin_override)
        {
            //override stdin to /dev/null
            int file_desc = open("/dev/null", O_WRONLY | O_CREAT);
            dup2(file_desc, 0);
        }

        //if process will be ran in the background, do not pass '&' argument from shell
        if(state.background)
        {
            //set last arg ( & ) to null, to not be passed into exec
            localArgs[passed_args - 1] = NULL;


            /* TEST CODE for testing signal handlers inherited from parent

            //set up exec'd process signal handler for to ignore a signal
            //struct sigaction ignore_action = {0};
            //ignore_action.sa_handler = SIG_IGN;
            //set up signal handler to IGNORE SIGINT : WILL BE INHERITED BY EXEC
            //sigaction(SIGINT, &ignore_action, NULL);

            */

        }
        else
        {
            //else, set last arg to pass to exec to NULL
            localArgs[passed_args] = NULL;
        }


        //exec command
        if(execvp(*localArgs, localArgs) < 0)
        {
            //error occured executing command.
            printf("%s: no such file or directory\n", localArgs[0]);
            fflush(stdout);
            process_status = 1;
            exit(1);
        }
    }



    //parent
    else{
        //if this is a foreground task
        if(!state.background){

            //wait for child process to terminate before returning control to terminal
            foreground_flag = 1;
            foreground_child = childPID;
            pid_t response = waitpid(childPID, &foreground_status, 0);
            foreground_flag = 0;
            foreground_child = DONE;

            //if process was killed by a signal, display signal that killed it
            if(WIFSIGNALED(foreground_status) != 0)
            {
                printf("terminated by signal %i\n", WTERMSIG(foreground_status));
                fflush(stdout);
            }

            //if there was a signal recieved while the foreground process was running, display it here (before user prompt)
            if(print_delayed_message)
            {
                if(!foreground_only_mode)
                {
                    printf("Entering foreground-only mode (& is now ignored)\n");
                    fflush(stdout);
                }
                else
                {
                    printf("Exiting foreground-only mode: \n");
                }
                print_delayed_message = 0;
            }




        }
        else //else this is a background task, add to list to monitor
        {
            //check to see if the parent has the space to monitor the child
            if((*state.current_backgrounds) >= MAX_BACKGROUND)
            {
                printf("Error: Maxmium backgrounds reached!: exiting...\n");
                //kill the child that spawned
                kill(childPID, SIGKILL);
                //kill all background processes and exit
                exitShell(state.background_processes, 1);
            }
            else
            {
                //add the child process to the list of background processes being tracked by the parent
                for(int i = 0; i < MAX_BACKGROUND; i++)
                {
                    //search for a empty place to store the child pid
                    if(state.background_processes[i] == DONE)
                    {
                        //set background_processes to monitor the childPID
                        state.background_processes[i] = childPID;
                        (*state.current_backgrounds)++;
                        printf("background pid is %i\n", childPID);
                        fflush(stdout);
                        //child added, safe to exit
                        break;
                    }
                }
            }

        }
        return;
    }


}

/*
Function that handles the main bulk of tokening the command line into nice array'd arguments

    The function utilizes the strtok function to parse a space-separated user input into arguments
    During this parsing, each token is checked for '$$' for pid exapnsion.

    If pid exapnsion occurs the following algorithm is used:
        example = "example$$expansion"
        before = "example"
        after = "expansion"

        argument = before-getpid-after
        argument = "example7543expansion"

    During this process the number of arguments are counted and are placed into a heap allocated string array via sprintf

*/
void processArguments(char* command_line, char** argument_pointers, int* arguments)
{
    //allocate memory to build a string before $$ is encountered, and after 
    char before$$[64] = {0};
    char after$$[64] = {0};
    //transform space delimeted words into array of characters
    //delimeter for breaking up command line
    const char s[2] = " ";
    //token = store current word
    char* token;

    //get first word from char buffer
    token = strtok(command_line, s);

    //used for pid expansion, if necessary
    char* index;

    //while there are words in the buffer to process
    while(token != NULL)
    {
        //if && is detected, expand strings of type X_&&_X to X_PID_X
        if(index = strstr(token, "$$"))
        {
            int pid = getpid();

            //copy everything before the $$ and place into before buffer
            strncpy(before$$, token, (index - token));
            //copy everything after the && and place into after buffer
            strcpy(after$$, (token + (index-token) + 2));
            //before-getpid-after
            snprintf(argument_pointers[*arguments], 255, "%s%i%s", before$$, getpid(), after$$);
            fflush(stdout);
        }

        //else just store the command in the command array
        else
        {
            snprintf(argument_pointers[*arguments], 255, "%s", token);
            fflush(stdout);
        }

        //get next word
        token = strtok(NULL, s);
        (*arguments)++;
    }   
}


//function to call when child signal is caught
/*
For this version of the program, this function is not used; however, an additional way
to manage background child processes would be to wait on them here. pid can be attained from the commented code
*/
void catchSIGCHILD(int signo, siginfo_t* child_info, void(*to_call))
{
    //process_pid = child_info->si_pid;
    //char* message = "Child signal recieved! Waiting on child, w/nohangup";
    //write(STDOUT_FILENO, message, 52);
}

/*
Defined action for sigint is to kill the foreground process and return control to the user.
*/
void catchSIGINT(int signo)
{

    //kill foreground child process, if one exists
    if(foreground_child != DONE)
    {
        kill(foreground_child, SIGINT);
    }

}

/*
If SIGTSTP ^Z signal is sent, the shell will change modes to either foreground_only_mode or background mode.
A foreground_only_mode flag is used to toggle between the two states.

foreground_only_mode = !foreground_only_mode ensures that we get the appropiate toggled response.

Since this signal can be sent while a foreground process is executing, a flag is used to ensure appropiate behavior:
    if a foreground process is running, the message will be delayed until the parent process waits for the child process.
    if no foreground process is running, the message is printed immediatally.
*/
void catchSIGTSTP(int signo)
{
    //if currently sitting at the command prompt: print instantly
    if(!foreground_flag)
    {
        if(!foreground_only_mode)
        {
            char* message = "\nEntering foreground-only mode (& is now ignored)\n: ";
            write(STDOUT_FILENO, message, 52);
        }
        else
        {
            char* message = "\nExiting foreground-only mode\n: ";
            write(STDOUT_FILENO, message, 32);
        }
        foreground_only_mode = !foreground_only_mode;
    }
    //foreground command is currently executing, change the mode still, but delay the message
    else
    {
        foreground_only_mode = !foreground_only_mode;
        print_delayed_message = 1;
    }
    
}

/*
Function that kills all currently running background processes and exits the shell program
*/
void exitShell(pid_t* background_processes, int exit_code)
{
    //For every child process managed:
    for(int i = 0; i < MAX_BACKGROUND; i++)
    {
        //if the process isn't finished:
        if(background_processes[i] != DONE)
        {
            //kill it
            kill(background_processes[i], SIGKILL);
        }
    }
    //exit the shell
    exit(0);
}
