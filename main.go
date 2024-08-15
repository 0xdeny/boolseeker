package main

import (
	"archive/zip"
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/briandowns/spinner"
)

func CheckApkTool() error {
	_, err := exec.LookPath("apktool")
	if err != nil {
		return fmt.Errorf("\033[31m✖️ apktool is not installed or not found in PATH\033[0m")
	}
	return nil
}

func isAPKFile(apkFile string) (bool, error) {
	fileInfo, err := os.Stat(apkFile)
	if err != nil {
		return false, fmt.Errorf("could not stat file: %w", err)
	}

	if fileInfo.IsDir() {
		return false, nil
	}

	zipReader, err := zip.OpenReader(apkFile)
	if err != nil {
		return false, nil
	}
	defer zipReader.Close()

	requiredFiles := map[string]bool{
		"AndroidManifest.xml": false,
		"classes.dex":         false,
	}

	for _, file := range zipReader.File {
		if _, found := requiredFiles[file.Name]; found {
			requiredFiles[file.Name] = true
		}
	}

	for _, found := range requiredFiles {
		if !found {
			return false, nil
		}
	}

	return true, nil
}

func DecodeAPK(apkFile, outputDirectory string, s *spinner.Spinner) error {
	if _, err := os.Stat(apkFile); os.IsNotExist(err) {
		return fmt.Errorf("\033[31m✖ The provided file does not exist: %s\033[0m", apkFile)
	}

	isValidAPK, err := isAPKFile(apkFile)
	if err != nil {
		return fmt.Errorf("\033[31m✖ The provided file is not a valid APK: %s\033[0m", apkFile)
	}

	if !isValidAPK {
		return fmt.Errorf("\033[31m✖ The provided file is not a valid APK: %s\033[0m", apkFile)
	}

	s.Suffix = fmt.Sprintf(" Decompiling APK: %s...", apkFile)
	cmd := exec.Command("apktool", "d", apkFile, "-o", outputDirectory)
	cmd.Stdout = nil
	cmd.Stderr = nil
	err = cmd.Run()

	if err != nil {
		return fmt.Errorf("\033[31m✖ Error decompiling APK: %w\033[0m", err)
	}
	return nil
}

func SearchKeywordsInMethod(methodContent string) ([]string, bool) {
	keywords := []string{"ro.hardware", "ro.kernel.qemu", "ro.product.device", "ro.build.product", "ro.product.model", "ro.build.fingerprint", "/sys/qemu_trace", "/dev/qemu_trace", "/dev/socket/qemud", "/dev/qemu_pipe", "/system/bin/netcfg", "/proc/cpuinfo", "/proc/tty/drivers", "magisk", "root", "test-keys", "superuser", "Superuser", "daemonsu", "99SuperSUDaemon", ".has_su_daemon", "genymotion", "emulator", "nox", "27042", "frida", "27043", "FridaGadget", "xposed", "MessageDigest", "getPackageInfo", "signature", "/system/app/Superuser.apk", "/system/xbin/su"}
	foundKeywords := []string{}

	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(methodContent), keyword) {
			foundKeywords = append(foundKeywords, keyword)
		}
	}

	return foundKeywords, len(foundKeywords) > 0
}

func FindBooleanMethodsInSmali(directory string) ([]string, map[string][]string, error) {
	var booleanMethods []string
	booleanMethodsWithKeywords := make(map[string][]string)
	methodPattern := regexp.MustCompile(`\.method.* (\w+)\(\)Z`)
	endMethodPattern := regexp.MustCompile(`\.end method`)

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".smali") {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			relativePath, err := filepath.Rel(directory, path)

			if err != nil {
				return err
			}

			className := strings.TrimSuffix(relativePath, ".smali")
			className = strings.ReplaceAll(className, "/", ".")
			className = strings.ReplaceAll(className, "$", ".")

			reader := bufio.NewReaderSize(file, 1<<20)
			var currentMethod string
			var inMethod bool
			var methodContent strings.Builder

			for {
				line, err := reader.ReadString('\n')

				if err != nil {
					if err == io.EOF {
						break
					}
					return err
				}

				if methodMatch := methodPattern.FindStringSubmatch(line); methodMatch != nil {
					currentMethod = methodMatch[1]
					inMethod = true
					methodContent.Reset()
				}

				if inMethod {
					methodContent.WriteString(line)
				}

				if inMethod && endMethodPattern.MatchString(line) {
					inMethod = false
					fullMethodName := fmt.Sprintf("%s.%s()", className, currentMethod)

					foundKeywords, found := SearchKeywordsInMethod(methodContent.String())
					if found {
						booleanMethods = append(booleanMethods, fullMethodName)
						booleanMethodsWithKeywords[fullMethodName] = foundKeywords
					} else {
						booleanMethods = append(booleanMethods, fullMethodName)
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		return nil, nil, err
	}
	return booleanMethods, booleanMethodsWithKeywords, nil
}

func CleanUp(directory string) {
	info, err := os.Stat(directory)

	if os.IsNotExist(err) {
		return
	} else if err != nil {
		fmt.Printf("\033[31m✖️ Error checking directory %s: %v\n", directory, err)
		return
	}

	if !info.IsDir() {
		return
	}

	err = os.RemoveAll(directory)
	if err != nil {
		fmt.Printf("\033[31m✖️ Error cleaning up directory %s: %v\n", directory, err)
	} else {
		fmt.Printf("\033[32m✔ Cleaned up directory %s\n", directory)
	}
}

func CustomUsage() {
	fmt.Println("\nUsage of boolseeker:")
	fmt.Println("  -a, --apk string")
	fmt.Println("        Path to the APK file to decode and analyze (required)")
	fmt.Println("  -o, --output string")
	fmt.Println("        Path to the output file for boolean method names (required)")
	fmt.Println("  -so")
	fmt.Println("        Enable searching in .so files")
}

func SearchInSoFiles(directory string, keywords []string) error {
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Color("red", "yellow", "blue", "green")

	s.Start()
	s.Suffix = " Searching for keywords in native functions within .so files..."

	foundKeywords := map[string][]string{}

	err := filepath.Walk(filepath.Join(directory, "lib"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".so") {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			for _, keyword := range keywords {
				if strings.Contains(strings.ToLower(string(content)), strings.ToLower(keyword)) {
					relativePath := strings.TrimPrefix(path, filepath.Join(directory))
					foundKeywords[relativePath] = append(foundKeywords[relativePath], keyword)
				}
			}
		}

		return nil
	})

	s.Stop()

	if err != nil {
		return err
	}

	if len(foundKeywords) > 0 {
		fmt.Println("\033[33m✔ Keywords found in the following .so files:\033[0m")
		for filePath, keywords := range foundKeywords {
			fmt.Printf("  \033[36m+ %s\033[0m \033[37m- \033[31mKeywords found: %s\033[0m\n", filePath, strings.Join(keywords, ", "))
		}
		fmt.Println()
	} else {
		fmt.Println("\033[31mX Keywords not found in any .so files.\033[0m")
		fmt.Println()
	}

	return nil
}

func main() {
	apkFile := flag.String("a", "", "Path to the APK file to decode and analyze (required)")
	flag.StringVar(apkFile, "apk", "", "Path to the APK file to decode and analyze (required)")
	outputFile := flag.String("o", "", "Path to the output file for boolean method names (required)")
	flag.StringVar(outputFile, "output", "", "Path to the output file for boolean method names (required)")
	searchSo := flag.Bool("so", false, "Enable searching in .so files")

	flag.Usage = CustomUsage
	flag.Parse()

	if *apkFile == "" || *outputFile == "" {
		fmt.Println("\033[31m✖️ Error: -a/--apk and -o/--output flags are required.\033[0m")
		flag.Usage()
		os.Exit(1)
	}

	decodedDirectory := strings.TrimSuffix(filepath.Base(*apkFile), ".apk")
	if _, err := os.Stat(decodedDirectory); err == nil {
		CleanUp(decodedDirectory)
	}

	err := CheckApkTool()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Color("red", "yellow", "blue", "green")
	s.Start()

	err = DecodeAPK(*apkFile, decodedDirectory, s)
	if err != nil {
		s.Stop()
		fmt.Println(err)
		os.Exit(1)
	}
	s.Stop()
	fmt.Printf("\033[32m✔ Successfully decompiled %s to %s\033[0m\n", *apkFile, decodedDirectory)

	s.Start()
	s.Suffix = fmt.Sprintf(" Searching for Java boolean methods and keywords in %s...", decodedDirectory)
	var booleanMethods []string
	booleanMethodsWithKeywords := make(map[string][]string)
	smaliDirs, err := filepath.Glob(filepath.Join(decodedDirectory, "smali*"))
	if err != nil {
		s.Stop()
		fmt.Println(err)
		os.Exit(1)
	}

	for _, smaliDir := range smaliDirs {
		methods, keywordsMap, err := FindBooleanMethodsInSmali(smaliDir)
		if err != nil {
			s.Stop()
			fmt.Println(err)
			os.Exit(1)
		}
		booleanMethods = append(booleanMethods, methods...)
		for k, v := range keywordsMap {
			booleanMethodsWithKeywords[k] = v
		}
	}

	s.Stop()

	methodSet := make(map[string]struct{})
	for _, method := range booleanMethods {
		methodSet[method] = struct{}{}
	}

	output, err := os.Create(*outputFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer output.Close()

	for method := range methodSet {
		_, err := output.WriteString(method + "\n")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	root_detection_keywords := []string{"magisk", "root", "test-keys", "superuser", "Superuser", "daemonsu", "99SuperSUDaemon", ".has_su_daemon", "/system/app/Superuser.apk", "/system/xbin/su"}
	emulator_detection_keywords := []string{"ro.hardware", "ro.kernel.qemu", "ro.product.device", "ro.build.product", "ro.product.model", "ro.build.fingerprint", "genymotion", "geny", "emulator", "nox", "/proc/tty/drivers", "/sys/qemu_trace", "/dev/qemu_trace", "/dev/socket/qemud", "/dev/qemu_pipe", "/system/bin/netcfg", "/proc/cpuinfo", "/proc/tty/drivers"}
	runtime_integrity_verification_keywords := []string{"27042", "frida", "27043", "FridaGadget", "xposed"}
	file_integrity_keywords := []string{"MessageDigest", "getPackageInfo", "signature"}
	fmt.Printf("\033[32m✔ Total number of unique boolean methods found: %d\033[0m\n", len(methodSet))
	fmt.Printf("\033[32m✔ Unique boolean methods written in %s\033[0m\n", *outputFile)

	if len(booleanMethodsWithKeywords) > 0 {
		foundKeywords := false
		methodsWithKeywords := make(map[string][]string)
		for method, keywords := range booleanMethodsWithKeywords {
			var filteredKeywords []string
			for _, keyword := range keywords {
				for _, runtimeKeyword := range root_detection_keywords {
					if keyword == runtimeKeyword {
						filteredKeywords = append(filteredKeywords, keyword)
					}
				}
			}
			if len(filteredKeywords) > 0 {
				foundKeywords = true
				methodsWithKeywords[method] = filteredKeywords
			}
		}

		if foundKeywords {
			fmt.Println()
			fmt.Println("\033[33m✔ Java boolean methods containing keywords about Rooted Device Detection:\033[0m")
			for method, keywords := range methodsWithKeywords {
				fmt.Printf("  \033[36m+ Java method: %s \033[0m- \033[31mKeywords found: %s\033[0m\n", method, strings.Join(keywords, ", "))
			}
			fmt.Println()
		} else {
			fmt.Println("\033[31mX No keywords about Rooted Device Detection found in Java boolean methods.\033[0m")
			fmt.Println()
		}

		foundKeywords = false

		methodsWithKeywords = make(map[string][]string)

		for method, keywords := range booleanMethodsWithKeywords {
			var filteredKeywords []string
			for _, keyword := range keywords {
				for _, runtimeKeyword := range emulator_detection_keywords {
					if keyword == runtimeKeyword {
						filteredKeywords = append(filteredKeywords, keyword)
					}
				}
			}
			if len(filteredKeywords) > 0 {
				foundKeywords = true
				methodsWithKeywords[method] = filteredKeywords
			}
		}

		if foundKeywords {
			fmt.Println("\033[33m✔ Java boolean methods containing keywords about Emulator Detection:\033[0m")
			for method, keywords := range methodsWithKeywords {
				fmt.Printf("  \033[36m+ Java method: %s \033[0m- \033[31mKeywords found: %s\033[0m\n", method, strings.Join(keywords, ", "))
			}
			fmt.Println()
		} else {
			fmt.Println("\033[31mX No keywords about Emulator Detection found in Java boolean methods.\033[0m")
			fmt.Println()
		}

		foundKeywords = false

		methodsWithKeywords = make(map[string][]string)

		for method, keywords := range booleanMethodsWithKeywords {
			var filteredKeywords []string
			for _, keyword := range keywords {
				for _, runtimeKeyword := range runtime_integrity_verification_keywords {
					if keyword == runtimeKeyword {
						filteredKeywords = append(filteredKeywords, keyword)
					}
				}
			}
			if len(filteredKeywords) > 0 {
				foundKeywords = true
				methodsWithKeywords[method] = filteredKeywords
			}
		}

		if foundKeywords {
			fmt.Println("\033[33m✔ Java boolean methods containing keywords about Runtime Integrity Verification:\033[0m")
			for method, keywords := range methodsWithKeywords {
				fmt.Printf("  \033[36m+ Java method: %s \033[0m- \033[31mKeywords found: %s\033[0m\n", method, strings.Join(keywords, ", "))
			}
			fmt.Println()
		} else {
			fmt.Println("\033[31mX No keywords about Runtime Integrity Verification found in Java boolean methods.\033[0m")
			fmt.Println()
		}

		foundKeywords = false

		methodsWithKeywords = make(map[string][]string)
		for method, keywords := range booleanMethodsWithKeywords {
			var filteredKeywords []string
			for _, keyword := range keywords {
				for _, runtimeKeyword := range file_integrity_keywords {
					if keyword == runtimeKeyword {
						filteredKeywords = append(filteredKeywords, keyword)
					}
				}
			}
			if len(filteredKeywords) > 0 {
				foundKeywords = true
				methodsWithKeywords[method] = filteredKeywords
			}
		}

		if foundKeywords {
			fmt.Println("\033[33m✔ Java boolean methods containing keywords about File Integrity Checks:\033[0m")
			for method, keywords := range methodsWithKeywords {
				fmt.Printf("  \033[36m+ Java method: %s \033[0m- \033[31mKeywords found: %s\033[0m\n", method, strings.Join(keywords, ", "))
			}
			fmt.Println()
		} else {
			fmt.Println("\033[31mX No keywords about File Integrity Checks found in Java boolean methods.\033[0m")
			fmt.Println()
		}

	} else {
		fmt.Println()
		fmt.Println("\033[31mX No keywords found in Java boolean methods.\033[0m")
		fmt.Println()
	}

	if *searchSo {
		so_keywords := []string{"frida", "xposed", "su", "root", "magisk", "/sbin/su", "test-keys"}
		err = SearchInSoFiles(decodedDirectory, so_keywords)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	CleanUp(decodedDirectory)
}
